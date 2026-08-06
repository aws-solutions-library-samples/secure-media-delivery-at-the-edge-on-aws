import {
  Stack,
  StackProps,
  Aws,
  RemovalPolicy,
  Duration,
  CfnOutput,
  CfnParameter,
  CustomResource,
  aws_cloudfront as cloudfront,
  aws_lambda as lambda,
  aws_apigateway as apigateway,
  aws_secretsmanager as secretsmanager,
  aws_s3 as s3,
  aws_s3_deployment as s3deploy,
  aws_iam as iam,
  aws_stepfunctions as sfn,
  aws_stepfunctions_tasks as tasks,
  aws_events as events,
  aws_events_targets as targets,
  aws_kinesis as kinesis,
  aws_wafv2 as wafv2,
  custom_resources,
} from "aws-cdk-lib";

import { HttpOrigin, RestApiOrigin, S3BucketOrigin } from "aws-cdk-lib/aws-cloudfront-origins";
import { NodejsFunction } from "aws-cdk-lib/aws-lambda-nodejs";
import { Construct } from "constructs";

export interface CTASecureMediaStackProps extends StackProps {
  readonly config?: any;
}

export class CTASecureMediaStack extends Stack {
  public readonly kvStore: cloudfront.KeyValueStore;
  public readonly distribution: cloudfront.Distribution;
  public readonly demoBucket: s3.Bucket;
  public readonly logStream: kinesis.Stream;
  
  constructor(scope: Construct, id: string, props: CTASecureMediaStackProps = {}) {
    super(scope, id, props);

    const enableDemo = new CfnParameter(this, "EnableDemo", {
      type: "String",
      default: "true",
      allowedValues: ["true", "false"],
      description: "Deploy demo website",
    });

    const bedrockModel = new CfnParameter(this, "BedrockModel", {
      type: "String",
      default: "amazon.nova-lite-v1:0",
      allowedValues: ["amazon.nova-pro-v1:0", "amazon.nova-lite-v1:0"],
      description: "Bedrock model for AI analysis",
    });

    const config = props.config || {
      main: {
        enableDemo: enableDemo.valueAsString === "true",
      },
      bedrock: {
        model: bedrockModel.valueAsString,
      }
    };

    // CTA signing key
    const signingSecret = new secretsmanager.Secret(this, "CTAKey", {
      generateSecretString: {
        secretStringTemplate: '{"algorithm":"HMAC-SHA256"}',
        generateStringKey: "signingKey",
        passwordLength: 64,
      },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // CloudFront KeyValueStore for revocation
    this.kvStore = new cloudfront.KeyValueStore(this, "CTARevocationStore", {
      comment: "CTA token revocation list",
    });

    // CTA validator function.
    //
    // Explicit addDependency on the KVS: CloudFront KeyValueStore is a
    // two-phase AWS resource (Provisioning -> Ready). The L2 construct
    // returns the ARN before the store is Ready, so without this
    // dependency CDK can order the CF Function's KeyValueStoreAssociations
    // before the KVS is Ready and CloudFormation fails with:
    //   "cannot be associated before the resource is provisioned"
    // The failure is intermittent — it depends on CDK's graph traversal
    // order — which makes it especially frustrating to debug on a fresh
    // deploy.
    const validator = new cloudfront.Function(this, "CTAValidator", {
      code: cloudfront.FunctionCode.fromFile({ filePath: "lambda/cta_token_validator.js" }),
      functionName: `${Aws.STACK_NAME}-CTA-Validator`,
      runtime: cloudfront.FunctionRuntime.JS_2_0,
      keyValueStore: this.kvStore,
    });
    validator.node.addDependency(this.kvStore);

    // Token generator (Node SDK)
    // NodejsFunction (esbuild) bundles the handler together with its
    // third-party dependency cbor-x, which is NOT provided by the Lambda
    // Node.js runtime. A plain Code.fromAsset("lambda") ships no node_modules,
    // so require('cbor-x') fails at module init and API Gateway returns a 502
    // with no CORS headers — surfacing in the browser as a CORS error.
    // The AWS SDK v3 packages (@aws-sdk/*) remain externalized by default
    // since they ARE present in the runtime.
    const generator = new NodejsFunction(this, "CTAGenerator", {
      runtime: lambda.Runtime.NODEJS_22_X,
      entry: "lambda/cta_token_generator.js",
      handler: "handler",
      timeout: Duration.seconds(10),
      environment: { SECRET_NAME: signingSecret.secretName },
    });

    // Token generator (Python SDK)
    const generatorPython = new lambda.Function(this, "CTAGeneratorPython", {
      runtime: lambda.Runtime.PYTHON_3_13,
      handler: "handler.handler",
      code: lambda.Code.fromAsset("lambda-python"),
      timeout: Duration.seconds(10),
      environment: { SECRET_NAME: signingSecret.secretName },
    });

    // Token generator (Ruby SDK)
    const generatorRuby = new lambda.Function(this, "CTAGeneratorRuby", {
      runtime: lambda.Runtime.RUBY_3_3,
      handler: "handler.handler",
      code: lambda.Code.fromAsset("lambda-ruby"),
      timeout: Duration.seconds(10),
      environment: { SECRET_NAME: signingSecret.secretName },
    });

    // Token revocation handler
    const revoker = new lambda.Function(this, "CTARevoker", {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: "cta_revocation.handler",
      code: lambda.Code.fromAsset("lambda"),
      timeout: Duration.seconds(10),
      environment: { KVS_ARN: this.kvStore.keyValueStoreArn },
    });

    signingSecret.grantRead(generator);
    signingSecret.grantRead(generatorPython);
    signingSecret.grantRead(generatorRuby);

    // Grant KVS update permission via IAM policy
    revoker.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ["cloudfront-keyvaluestore:PutKey", "cloudfront-keyvaluestore:DescribeKeyValueStore"],
      resources: [this.kvStore.keyValueStoreArn],
    }));

    // --- Key sync Lambda (custom resource + rotation) ---
    const syncKeysToKvs = new lambda.Function(this, "SyncKeysToKvs", {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: "index.handler",
      code: lambda.Code.fromAsset("lambda/sync_keys"),
      timeout: Duration.seconds(30),
      environment: {
        SECRET_NAME: signingSecret.secretName,
        KVS_ARN: this.kvStore.keyValueStoreArn,
      },
    });

    signingSecret.grantRead(syncKeysToKvs);
    signingSecret.grantWrite(syncKeysToKvs);
    syncKeysToKvs.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        "cloudfront-keyvaluestore:PutKey",
        "cloudfront-keyvaluestore:DescribeKeyValueStore",
      ],
      resources: [this.kvStore.keyValueStoreArn],
    }));

    // Custom resource: sync key to KVS on deploy
    const keySyncProvider = new custom_resources.Provider(this, "KeySyncProvider", {
      onEventHandler: syncKeysToKvs,
    });

    new CustomResource(this, "KeySyncResource", {
      serviceToken: keySyncProvider.serviceToken,
      properties: {
        // Force update on each deploy to ensure key is synced
        Timestamp: Date.now().toString(),
      },
    });

    // --- Key rotation workflow ---
    const rotateKeyTask = new tasks.LambdaInvoke(this, "RotateSigningKey", {
      lambdaFunction: syncKeysToKvs,
      payload: sfn.TaskInput.fromObject({ rotate: true }),
      resultPath: sfn.JsonPath.DISCARD,
    });

    const rotationWorkflow = new sfn.StateMachine(this, "KeyRotationWorkflow", {
      stateMachineName: `${Aws.STACK_NAME}_RotateKeys`,
      definitionBody: sfn.DefinitionBody.fromChainable(rotateKeyTask),
      timeout: Duration.minutes(5),
    });

    // Rotate keys monthly by default
    const rotationSchedule = config.main.rotationFrequency || "30d";
    const rotationRate = this.parseRotationRate(rotationSchedule);
    new events.Rule(this, "KeyRotationSchedule", {
      schedule: events.Schedule.rate(rotationRate),
      targets: [new targets.SfnStateMachine(rotationWorkflow)],
    });

    // API Gateway
    const api = new apigateway.RestApi(this, "CTAAPI", {
      restApiName: "CTA Token API",
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
      },
    });

    // Attach CORS headers to API Gateway's default gateway responses so that
    // integration errors (e.g. a Lambda 5xx/timeout, or a 4xx) still carry
    // Access-Control-Allow-Origin. Without this, an errored request returns a
    // response with no CORS header, which browsers surface as a misleading
    // "blocked by CORS policy" error that masks the real status code.
    const corsResponseHeaders = {
      "Access-Control-Allow-Origin": "'*'",
      "Access-Control-Allow-Headers": "'*'",
    };
    api.addGatewayResponse("Default4XX", {
      type: apigateway.ResponseType.DEFAULT_4XX,
      responseHeaders: corsResponseHeaders,
    });
    api.addGatewayResponse("Default5XX", {
      type: apigateway.ResponseType.DEFAULT_5XX,
      responseHeaders: corsResponseHeaders,
    });

    const tokenResource = api.root.addResource("token");
    tokenResource.addMethod("POST", new apigateway.LambdaIntegration(generator));

    const tokenPythonResource = api.root.addResource("token-python");
    tokenPythonResource.addMethod("POST", new apigateway.LambdaIntegration(generatorPython));

    const tokenRubyResource = api.root.addResource("token-ruby");
    tokenRubyResource.addMethod("POST", new apigateway.LambdaIntegration(generatorRuby));
    
    const revokeResource = api.root.addResource("revoke");
    revokeResource.addMethod("POST", new apigateway.LambdaIntegration(revoker));

    // WAFv2 Web ACL — rate-limit POST /api/token per source IP.
    //: automated-scraping mitigation. Rate-based rules use a
    // rolling 5-minute window; 300 req/5min ≈ 60 req/min per IP, well
    // above legitimate player traffic (mint once → 2h TTL → next mint)
    // but tight enough to stop a mint-your-own-token scraper.
    // Blocked requests get a custom 429 response instead of the default 403.
    const rateLimitBody = "CTAWebAclRateLimit429";
    const webAcl = new wafv2.CfnWebACL(this, "CTAWebAcl", {
      name: `${Aws.STACK_NAME}-token-rate-limit`,
      description: "Rate-limit POST /api/token to mitigate automated CWT minting",
      scope: "CLOUDFRONT",
      defaultAction: { allow: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: `${Aws.STACK_NAME}-web-acl`,
        sampledRequestsEnabled: true,
      },
      customResponseBodies: {
        [rateLimitBody]: {
          contentType: "APPLICATION_JSON",
          content: JSON.stringify({ error: "rate_limited", message: "Too many token mint requests from this IP; try again in a few minutes." }),
        },
      },
      rules: [{
        name: "TokenMintRateLimit",
        priority: 0,
        action: {
          block: {
            customResponse: {
              responseCode: 429,
              customResponseBodyKey: rateLimitBody,
            },
          },
        },
        statement: {
          rateBasedStatement: {
            limit: 300,
            aggregateKeyType: "IP",
            scopeDownStatement: {
              byteMatchStatement: {
                fieldToMatch: { uriPath: {} },
                positionalConstraint: "STARTS_WITH",
                searchString: "/api/token",
                textTransformations: [{ priority: 0, type: "NONE" }],
              },
            },
          },
        },
        visibilityConfig: {
          cloudWatchMetricsEnabled: true,
          metricName: `${Aws.STACK_NAME}-token-rate-limit`,
          sampledRequestsEnabled: true,
        },
      }],
    });

    // Demo website (conditional)
    let distribution: cloudfront.Distribution;
    let demoBucket: s3.Bucket | undefined;

    if (config.main.enableDemo) {
      demoBucket = new s3.Bucket(this, "DemoWebsite", {
        removalPolicy: RemovalPolicy.DESTROY,
        autoDeleteObjects: true,
      });

      new s3deploy.BucketDeployment(this, "DeployDemoSite", {
        sources: [s3deploy.Source.asset("resources/demo-website")],
        destinationBucket: demoBucket,
        destinationKeyPrefix: "website",
        prune: false,
      });

      distribution = new cloudfront.Distribution(this, "CTADistribution", {
        webAclId: webAcl.attrArn,
        defaultBehavior: {
          origin: new HttpOrigin("cdn.mediaplaypen.com"),
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
          cachePolicy: new cloudfront.CachePolicy(this, "CTACachePolicy", {
            headerBehavior: cloudfront.CacheHeaderBehavior.allowList(
              "CloudFront-Viewer-Country"
            ),
          }),
          originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
          functionAssociations: [{
            function: validator,
            eventType: cloudfront.FunctionEventType.VIEWER_REQUEST,
          }],
        },
        additionalBehaviors: {
          "/api/*": {
            origin: new RestApiOrigin(api),
            viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
            cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
            originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
          },
          "/website/*": {
            origin: S3BucketOrigin.withOriginAccessControl(demoBucket),
          },
        },
      });

    } else {
      distribution = new cloudfront.Distribution(this, "CTADistribution", {
        webAclId: webAcl.attrArn,
        defaultBehavior: {
          origin: new RestApiOrigin(api),
          functionAssociations: [{
            function: validator,
            eventType: cloudfront.FunctionEventType.VIEWER_REQUEST,
          }],
        },
      });
    }

    this.distribution = distribution;
    if (config.main.enableDemo) {
      this.demoBucket = demoBucket!;
    }

    // --- Real-Time Logging via Kinesis ---
    const logStream = new kinesis.Stream(this, "RealtimeLogStream", {
      streamMode: kinesis.StreamMode.ON_DEMAND,
      retentionPeriod: Duration.hours(24),
    });
    this.logStream = logStream;

    const cfKinesisRole = new iam.Role(this, "CloudFrontKinesisRole", {
      assumedBy: new iam.ServicePrincipal("cloudfront.amazonaws.com"),
    });
    logStream.grantWrite(cfKinesisRole);

    const realtimeLogConfig = new cloudfront.CfnRealtimeLogConfig(this, "RealtimeLogConfig", {
      name: `${Aws.STACK_NAME}-realtime-logs`,
      samplingRate: 100,
      endPoints: [{
        streamType: "Kinesis",
        kinesisStreamConfig: {
          roleArn: cfKinesisRole.roleArn,
          streamArn: logStream.streamArn,
        },
      }],
      fields: [
        "timestamp", "c-ip", "sc-status", "cs-uri-stem", "cs-method",
        "cs-host", "cs-user-agent", "sc-bytes", "time-taken", "c-country",
      ],
    });

    // Attach real-time logs to the default cache behavior
    const cfnDist = distribution.node.defaultChild as cloudfront.CfnDistribution;
    cfnDist.addPropertyOverride(
      "DistributionConfig.DefaultCacheBehavior.RealtimeLogConfigArn",
      realtimeLogConfig.attrArn
    );

    // --- Dashboard: list revoked sessions from KVS ---
    const listRevoked = new lambda.Function(this, "ListRevoked", {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: "list_revoked.handler",
      code: lambda.Code.fromAsset("lambda"),
      timeout: Duration.seconds(10),
      environment: { KVS_ARN: this.kvStore.keyValueStoreArn },
    });
    listRevoked.addToRolePolicy(new iam.PolicyStatement({
      actions: ["cloudfront-keyvaluestore:ListKeys", "cloudfront-keyvaluestore:DescribeKeyValueStore"],
      resources: [this.kvStore.keyValueStoreArn],
    }));

    // Add /revoked to the existing API
    api.root.addResource("revoked").addMethod("GET",
      new apigateway.LambdaIntegration(listRevoked)
    );

    // Deploy dashboard HTML (alongside demo site if enabled)
    if (config.main.enableDemo) {
      new s3deploy.BucketDeployment(this, "DeployDashboard", {
        sources: [
          s3deploy.Source.asset("resources/dashboard"),
          s3deploy.Source.data("config.js",
            `window.CTA_CONFIG={apiEndpoint:"${api.url.replace(/\/$/,'')}",cdnDomain:"https://${distribution.distributionDomainName}"};`
          ),
        ],
        destinationBucket: demoBucket!,
        destinationKeyPrefix: "website",
        prune: false,
      });
    }

    // --- KVS Cleanup: purge expired revocations on a schedule ---
    const kvsCleanup = new lambda.Function(this, "KvsCleanup", {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: "kvs_cleanup.handler",
      code: lambda.Code.fromAsset("lambda"),
      timeout: Duration.minutes(2),
      environment: { KVS_ARN: this.kvStore.keyValueStoreArn, TTL_HOURS: "24" },
    });
    kvsCleanup.addToRolePolicy(new iam.PolicyStatement({
      actions: ["cloudfront-keyvaluestore:ListKeys", "cloudfront-keyvaluestore:DeleteKey", "cloudfront-keyvaluestore:DescribeKeyValueStore"],
      resources: [this.kvStore.keyValueStoreArn],
    }));
    new events.Rule(this, "KvsCleanupSchedule", {
      schedule: events.Schedule.rate(Duration.hours(1)),
      targets: [new targets.LambdaFunction(kvsCleanup)],
    });

    // Outputs
    new CfnOutput(this, "APIEndpoint", { 
      value: `https://${distribution.distributionDomainName}/api`,
      description: "CTA API Endpoint"
    });
    
    if (config.main.enableDemo) {
      new CfnOutput(this, "DemoWebsiteUrl", { 
        value: `https://${distribution.distributionDomainName}/website/index.html`,
        description: "CTA Demo Website URL"
      });
    }
    
    new CfnOutput(this, "KeyValueStoreId", { 
      value: this.kvStore.keyValueStoreId,
      description: "CloudFront KeyValueStore ID"
    });

    new CfnOutput(this, "SecretArn", {
      value: signingSecret.secretArn,
      description: "CTA signing secret ARN"
    });

    new CfnOutput(this, "CTAStandard", {
      value: "CTA-5007-B",
      description: "Implemented standard version"
    });

    new CfnOutput(this, "RotationWorkflow", {
      value: rotationWorkflow.stateMachineName,
      description: "Key rotation Step Functions workflow"
    });

    new CfnOutput(this, "WebAclArn", {
      value: webAcl.attrArn,
      description: "WAFv2 Web ACL — rate-limits POST /api/token"
    });
  }

  private parseRotationRate(rate: string): Duration {
    const match = rate.match(/^(\d+)([mhd])$/);
    if (!match) return Duration.days(30);
    const value = parseInt(match[1]);
    switch (match[2]) {
      case 'm': return Duration.minutes(value);
      case 'h': return Duration.hours(value);
      case 'd': return Duration.days(value);
      default: return Duration.days(30);
    }
  }
}
