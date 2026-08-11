"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CTASecureMediaStack = void 0;
const aws_cdk_lib_1 = require("aws-cdk-lib");
const aws_cloudfront_origins_1 = require("aws-cdk-lib/aws-cloudfront-origins");
const aws_lambda_nodejs_1 = require("aws-cdk-lib/aws-lambda-nodejs");
class CTASecureMediaStack extends aws_cdk_lib_1.Stack {
    constructor(scope, id, props = {}) {
        super(scope, id, props);
        const enableDemo = new aws_cdk_lib_1.CfnParameter(this, "EnableDemo", {
            type: "String",
            default: "true",
            allowedValues: ["true", "false"],
            description: "Deploy demo website",
        });
        const bedrockModel = new aws_cdk_lib_1.CfnParameter(this, "BedrockModel", {
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
        const signingSecret = new aws_cdk_lib_1.aws_secretsmanager.Secret(this, "CTAKey", {
            generateSecretString: {
                secretStringTemplate: '{"algorithm":"HMAC-SHA256"}',
                generateStringKey: "signingKey",
                passwordLength: 64,
            },
            removalPolicy: aws_cdk_lib_1.RemovalPolicy.DESTROY,
        });
        // CloudFront KeyValueStore for revocation
        this.kvStore = new aws_cdk_lib_1.aws_cloudfront.KeyValueStore(this, "CTARevocationStore", {
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
        const validator = new aws_cdk_lib_1.aws_cloudfront.Function(this, "CTAValidator", {
            code: aws_cdk_lib_1.aws_cloudfront.FunctionCode.fromFile({ filePath: "lambda/cta_token_validator.js" }),
            functionName: `${aws_cdk_lib_1.Aws.STACK_NAME}-CTA-Validator`,
            runtime: aws_cdk_lib_1.aws_cloudfront.FunctionRuntime.JS_2_0,
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
        const generator = new aws_lambda_nodejs_1.NodejsFunction(this, "CTAGenerator", {
            runtime: aws_cdk_lib_1.aws_lambda.Runtime.NODEJS_22_X,
            entry: "lambda/cta_token_generator.js",
            handler: "handler",
            timeout: aws_cdk_lib_1.Duration.seconds(10),
            environment: { SECRET_NAME: signingSecret.secretName },
        });
        // Token generator (Python SDK)
        const generatorPython = new aws_cdk_lib_1.aws_lambda.Function(this, "CTAGeneratorPython", {
            runtime: aws_cdk_lib_1.aws_lambda.Runtime.PYTHON_3_13,
            handler: "handler.handler",
            code: aws_cdk_lib_1.aws_lambda.Code.fromAsset("lambda-python"),
            timeout: aws_cdk_lib_1.Duration.seconds(10),
            environment: { SECRET_NAME: signingSecret.secretName },
        });
        // Token generator (Ruby SDK)
        const generatorRuby = new aws_cdk_lib_1.aws_lambda.Function(this, "CTAGeneratorRuby", {
            runtime: aws_cdk_lib_1.aws_lambda.Runtime.RUBY_3_3,
            handler: "handler.handler",
            code: aws_cdk_lib_1.aws_lambda.Code.fromAsset("lambda-ruby"),
            timeout: aws_cdk_lib_1.Duration.seconds(10),
            environment: { SECRET_NAME: signingSecret.secretName },
        });
        // Token revocation handler
        const revoker = new aws_cdk_lib_1.aws_lambda.Function(this, "CTARevoker", {
            runtime: aws_cdk_lib_1.aws_lambda.Runtime.NODEJS_22_X,
            handler: "cta_revocation.handler",
            code: aws_cdk_lib_1.aws_lambda.Code.fromAsset("lambda"),
            timeout: aws_cdk_lib_1.Duration.seconds(10),
            environment: { KVS_ARN: this.kvStore.keyValueStoreArn },
        });
        signingSecret.grantRead(generator);
        signingSecret.grantRead(generatorPython);
        signingSecret.grantRead(generatorRuby);
        // Grant KVS update permission via IAM policy
        revoker.addToRolePolicy(new aws_cdk_lib_1.aws_iam.PolicyStatement({
            effect: aws_cdk_lib_1.aws_iam.Effect.ALLOW,
            actions: ["cloudfront-keyvaluestore:PutKey", "cloudfront-keyvaluestore:DescribeKeyValueStore"],
            resources: [this.kvStore.keyValueStoreArn],
        }));
        // --- Key sync Lambda (custom resource + rotation) ---
        const syncKeysToKvs = new aws_cdk_lib_1.aws_lambda.Function(this, "SyncKeysToKvs", {
            runtime: aws_cdk_lib_1.aws_lambda.Runtime.NODEJS_22_X,
            handler: "index.handler",
            code: aws_cdk_lib_1.aws_lambda.Code.fromAsset("lambda/sync_keys"),
            timeout: aws_cdk_lib_1.Duration.seconds(30),
            environment: {
                SECRET_NAME: signingSecret.secretName,
                KVS_ARN: this.kvStore.keyValueStoreArn,
            },
        });
        signingSecret.grantRead(syncKeysToKvs);
        signingSecret.grantWrite(syncKeysToKvs);
        syncKeysToKvs.addToRolePolicy(new aws_cdk_lib_1.aws_iam.PolicyStatement({
            effect: aws_cdk_lib_1.aws_iam.Effect.ALLOW,
            actions: [
                "cloudfront-keyvaluestore:PutKey",
                "cloudfront-keyvaluestore:DescribeKeyValueStore",
            ],
            resources: [this.kvStore.keyValueStoreArn],
        }));
        // Custom resource: sync key to KVS on deploy
        const keySyncProvider = new aws_cdk_lib_1.custom_resources.Provider(this, "KeySyncProvider", {
            onEventHandler: syncKeysToKvs,
        });
        new aws_cdk_lib_1.CustomResource(this, "KeySyncResource", {
            serviceToken: keySyncProvider.serviceToken,
            properties: {
                // Force update on each deploy to ensure key is synced
                Timestamp: Date.now().toString(),
            },
        });
        // --- Key rotation workflow ---
        const rotateKeyTask = new aws_cdk_lib_1.aws_stepfunctions_tasks.LambdaInvoke(this, "RotateSigningKey", {
            lambdaFunction: syncKeysToKvs,
            payload: aws_cdk_lib_1.aws_stepfunctions.TaskInput.fromObject({ rotate: true }),
            resultPath: aws_cdk_lib_1.aws_stepfunctions.JsonPath.DISCARD,
        });
        const rotationWorkflow = new aws_cdk_lib_1.aws_stepfunctions.StateMachine(this, "KeyRotationWorkflow", {
            stateMachineName: `${aws_cdk_lib_1.Aws.STACK_NAME}_RotateKeys`,
            definitionBody: aws_cdk_lib_1.aws_stepfunctions.DefinitionBody.fromChainable(rotateKeyTask),
            timeout: aws_cdk_lib_1.Duration.minutes(5),
        });
        // Rotate keys monthly by default
        const rotationSchedule = config.main.rotationFrequency || "30d";
        const rotationRate = this.parseRotationRate(rotationSchedule);
        new aws_cdk_lib_1.aws_events.Rule(this, "KeyRotationSchedule", {
            schedule: aws_cdk_lib_1.aws_events.Schedule.rate(rotationRate),
            targets: [new aws_cdk_lib_1.aws_events_targets.SfnStateMachine(rotationWorkflow)],
        });
        // API Gateway
        const api = new aws_cdk_lib_1.aws_apigateway.RestApi(this, "CTAAPI", {
            restApiName: "CTA Token API",
            defaultCorsPreflightOptions: {
                allowOrigins: aws_cdk_lib_1.aws_apigateway.Cors.ALL_ORIGINS,
                allowMethods: aws_cdk_lib_1.aws_apigateway.Cors.ALL_METHODS,
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
            type: aws_cdk_lib_1.aws_apigateway.ResponseType.DEFAULT_4XX,
            responseHeaders: corsResponseHeaders,
        });
        api.addGatewayResponse("Default5XX", {
            type: aws_cdk_lib_1.aws_apigateway.ResponseType.DEFAULT_5XX,
            responseHeaders: corsResponseHeaders,
        });
        const tokenResource = api.root.addResource("token");
        tokenResource.addMethod("POST", new aws_cdk_lib_1.aws_apigateway.LambdaIntegration(generator));
        const tokenPythonResource = api.root.addResource("token-python");
        tokenPythonResource.addMethod("POST", new aws_cdk_lib_1.aws_apigateway.LambdaIntegration(generatorPython));
        const tokenRubyResource = api.root.addResource("token-ruby");
        tokenRubyResource.addMethod("POST", new aws_cdk_lib_1.aws_apigateway.LambdaIntegration(generatorRuby));
        const revokeResource = api.root.addResource("revoke");
        revokeResource.addMethod("POST", new aws_cdk_lib_1.aws_apigateway.LambdaIntegration(revoker));
        // WAFv2 Web ACL — rate-limit POST /api/token per source IP.
        //: automated-scraping mitigation. Rate-based rules use a
        // rolling 5-minute window; 300 req/5min ≈ 60 req/min per IP, well
        // above legitimate player traffic (mint once → 2h TTL → next mint)
        // but tight enough to stop a mint-your-own-token scraper.
        // Blocked requests get a custom 429 response instead of the default 403.
        const rateLimitBody = "CTAWebAclRateLimit429";
        const webAcl = new aws_cdk_lib_1.aws_wafv2.CfnWebACL(this, "CTAWebAcl", {
            name: `${aws_cdk_lib_1.Aws.STACK_NAME}-token-rate-limit`,
            description: "Rate-limit POST /api/token to mitigate automated CWT minting",
            scope: "CLOUDFRONT",
            defaultAction: { allow: {} },
            visibilityConfig: {
                cloudWatchMetricsEnabled: true,
                metricName: `${aws_cdk_lib_1.Aws.STACK_NAME}-web-acl`,
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
                        metricName: `${aws_cdk_lib_1.Aws.STACK_NAME}-token-rate-limit`,
                        sampledRequestsEnabled: true,
                    },
                }],
        });
        // Demo website (conditional)
        let distribution;
        let demoBucket;
        if (config.main.enableDemo) {
            demoBucket = new aws_cdk_lib_1.aws_s3.Bucket(this, "DemoWebsite", {
                removalPolicy: aws_cdk_lib_1.RemovalPolicy.DESTROY,
                autoDeleteObjects: true,
            });
            new aws_cdk_lib_1.aws_s3_deployment.BucketDeployment(this, "DeployDemoSite", {
                sources: [aws_cdk_lib_1.aws_s3_deployment.Source.asset("resources/demo-website")],
                destinationBucket: demoBucket,
                destinationKeyPrefix: "website",
                prune: false,
            });
            distribution = new aws_cdk_lib_1.aws_cloudfront.Distribution(this, "CTADistribution", {
                webAclId: webAcl.attrArn,
                defaultBehavior: {
                    origin: new aws_cloudfront_origins_1.HttpOrigin("cdn.mediaplaypen.com"),
                    viewerProtocolPolicy: aws_cdk_lib_1.aws_cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                    cachePolicy: new aws_cdk_lib_1.aws_cloudfront.CachePolicy(this, "CTACachePolicy", {
                        headerBehavior: aws_cdk_lib_1.aws_cloudfront.CacheHeaderBehavior.allowList("CloudFront-Viewer-Country"),
                    }),
                    responseHeadersPolicy: new aws_cdk_lib_1.aws_cloudfront.ResponseHeadersPolicy(this, "CTACorsResponsePolicy", {
                        responseHeadersPolicyName: `${aws_cdk_lib_1.Aws.STACK_NAME}-CTA-CORS`,
                        corsBehavior: {
                            accessControlAllowOrigins: ["*"],
                            accessControlAllowHeaders: ["CTA-Common-Access-Token", "Content-Type"],
                            accessControlAllowMethods: ["GET", "HEAD", "OPTIONS"],
                            accessControlExposeHeaders: ["CTA-Common-Access-Token"],
                            accessControlAllowCredentials: false,
                            accessControlMaxAge: aws_cdk_lib_1.Duration.hours(24),
                            originOverride: true,
                        },
                    }),
                    originRequestPolicy: aws_cdk_lib_1.aws_cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
                    functionAssociations: [{
                            function: validator,
                            eventType: aws_cdk_lib_1.aws_cloudfront.FunctionEventType.VIEWER_REQUEST,
                        }],
                },
                additionalBehaviors: {
                    "/api/*": {
                        origin: new aws_cloudfront_origins_1.RestApiOrigin(api),
                        viewerProtocolPolicy: aws_cdk_lib_1.aws_cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                        allowedMethods: aws_cdk_lib_1.aws_cloudfront.AllowedMethods.ALLOW_ALL,
                        cachePolicy: aws_cdk_lib_1.aws_cloudfront.CachePolicy.CACHING_DISABLED,
                        originRequestPolicy: aws_cdk_lib_1.aws_cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
                    },
                    "/website/*": {
                        origin: aws_cloudfront_origins_1.S3BucketOrigin.withOriginAccessControl(demoBucket),
                    },
                },
            });
        }
        else {
            distribution = new aws_cdk_lib_1.aws_cloudfront.Distribution(this, "CTADistribution", {
                webAclId: webAcl.attrArn,
                defaultBehavior: {
                    origin: new aws_cloudfront_origins_1.RestApiOrigin(api),
                    functionAssociations: [{
                            function: validator,
                            eventType: aws_cdk_lib_1.aws_cloudfront.FunctionEventType.VIEWER_REQUEST,
                        }],
                },
            });
        }
        this.distribution = distribution;
        if (config.main.enableDemo) {
            this.demoBucket = demoBucket;
        }
        // --- Real-Time Logging via Kinesis ---
        const logStream = new aws_cdk_lib_1.aws_kinesis.Stream(this, "RealtimeLogStream", {
            streamMode: aws_cdk_lib_1.aws_kinesis.StreamMode.ON_DEMAND,
            retentionPeriod: aws_cdk_lib_1.Duration.hours(24),
        });
        this.logStream = logStream;
        const cfKinesisRole = new aws_cdk_lib_1.aws_iam.Role(this, "CloudFrontKinesisRole", {
            assumedBy: new aws_cdk_lib_1.aws_iam.ServicePrincipal("cloudfront.amazonaws.com"),
        });
        logStream.grantWrite(cfKinesisRole);
        const realtimeLogConfig = new aws_cdk_lib_1.aws_cloudfront.CfnRealtimeLogConfig(this, "RealtimeLogConfig", {
            name: `${aws_cdk_lib_1.Aws.STACK_NAME}-realtime-logs`,
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
        const cfnDist = distribution.node.defaultChild;
        cfnDist.addPropertyOverride("DistributionConfig.DefaultCacheBehavior.RealtimeLogConfigArn", realtimeLogConfig.attrArn);
        // --- Dashboard: list revoked sessions from KVS ---
        const listRevoked = new aws_cdk_lib_1.aws_lambda.Function(this, "ListRevoked", {
            runtime: aws_cdk_lib_1.aws_lambda.Runtime.NODEJS_22_X,
            handler: "list_revoked.handler",
            code: aws_cdk_lib_1.aws_lambda.Code.fromAsset("lambda"),
            timeout: aws_cdk_lib_1.Duration.seconds(10),
            environment: { KVS_ARN: this.kvStore.keyValueStoreArn },
        });
        listRevoked.addToRolePolicy(new aws_cdk_lib_1.aws_iam.PolicyStatement({
            actions: ["cloudfront-keyvaluestore:ListKeys", "cloudfront-keyvaluestore:DescribeKeyValueStore"],
            resources: [this.kvStore.keyValueStoreArn],
        }));
        // Add /revoked to the existing API
        api.root.addResource("revoked").addMethod("GET", new aws_cdk_lib_1.aws_apigateway.LambdaIntegration(listRevoked));
        // Deploy dashboard HTML (alongside demo site if enabled)
        if (config.main.enableDemo) {
            new aws_cdk_lib_1.aws_s3_deployment.BucketDeployment(this, "DeployDashboard", {
                sources: [
                    aws_cdk_lib_1.aws_s3_deployment.Source.asset("resources/dashboard"),
                    aws_cdk_lib_1.aws_s3_deployment.Source.data("config.js", `window.CTA_CONFIG={apiEndpoint:"${api.url.replace(/\/$/, '')}",cdnDomain:"https://${distribution.distributionDomainName}"};`),
                ],
                destinationBucket: demoBucket,
                destinationKeyPrefix: "website",
                prune: false,
            });
        }
        // --- KVS Cleanup: purge expired revocations on a schedule ---
        const kvsCleanup = new aws_cdk_lib_1.aws_lambda.Function(this, "KvsCleanup", {
            runtime: aws_cdk_lib_1.aws_lambda.Runtime.NODEJS_22_X,
            handler: "kvs_cleanup.handler",
            code: aws_cdk_lib_1.aws_lambda.Code.fromAsset("lambda"),
            timeout: aws_cdk_lib_1.Duration.minutes(2),
            environment: { KVS_ARN: this.kvStore.keyValueStoreArn, TTL_HOURS: "24" },
        });
        kvsCleanup.addToRolePolicy(new aws_cdk_lib_1.aws_iam.PolicyStatement({
            actions: ["cloudfront-keyvaluestore:ListKeys", "cloudfront-keyvaluestore:DeleteKey", "cloudfront-keyvaluestore:DescribeKeyValueStore"],
            resources: [this.kvStore.keyValueStoreArn],
        }));
        new aws_cdk_lib_1.aws_events.Rule(this, "KvsCleanupSchedule", {
            schedule: aws_cdk_lib_1.aws_events.Schedule.rate(aws_cdk_lib_1.Duration.hours(1)),
            targets: [new aws_cdk_lib_1.aws_events_targets.LambdaFunction(kvsCleanup)],
        });
        // Outputs
        new aws_cdk_lib_1.CfnOutput(this, "APIEndpoint", {
            value: `https://${distribution.distributionDomainName}/api`,
            description: "CTA API Endpoint"
        });
        if (config.main.enableDemo) {
            new aws_cdk_lib_1.CfnOutput(this, "DemoWebsiteUrl", {
                value: `https://${distribution.distributionDomainName}/website/index-path.html`,
                description: "CTA Demo Website — Path Token Mode"
            });
            new aws_cdk_lib_1.CfnOutput(this, "DemoWebsiteHeaderUrl", {
                value: `https://${distribution.distributionDomainName}/website/index-header.html`,
                description: "CTA Demo Website — Header-Only Token Mode"
            });
            new aws_cdk_lib_1.CfnOutput(this, "DemoWebsiteHybridUrl", {
                value: `https://${distribution.distributionDomainName}/website/index-hybrid.html`,
                description: "CTA Demo Website — Hybrid (Path Init → Header Renewal)"
            });
        }
        new aws_cdk_lib_1.CfnOutput(this, "KeyValueStoreId", {
            value: this.kvStore.keyValueStoreId,
            description: "CloudFront KeyValueStore ID"
        });
        new aws_cdk_lib_1.CfnOutput(this, "SecretArn", {
            value: signingSecret.secretArn,
            description: "CTA signing secret ARN"
        });
        new aws_cdk_lib_1.CfnOutput(this, "CTAStandard", {
            value: "CTA-5007-B",
            description: "Implemented standard version"
        });
        new aws_cdk_lib_1.CfnOutput(this, "RotationWorkflow", {
            value: rotationWorkflow.stateMachineName,
            description: "Key rotation Step Functions workflow"
        });
        new aws_cdk_lib_1.CfnOutput(this, "WebAclArn", {
            value: webAcl.attrArn,
            description: "WAFv2 Web ACL — rate-limits POST /api/token"
        });
    }
    parseRotationRate(rate) {
        const match = rate.match(/^(\d+)([mhd])$/);
        if (!match)
            return aws_cdk_lib_1.Duration.days(30);
        const value = parseInt(match[1]);
        switch (match[2]) {
            case 'm': return aws_cdk_lib_1.Duration.minutes(value);
            case 'h': return aws_cdk_lib_1.Duration.hours(value);
            case 'd': return aws_cdk_lib_1.Duration.days(value);
            default: return aws_cdk_lib_1.Duration.days(30);
        }
    }
}
exports.CTASecureMediaStack = CTASecureMediaStack;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY3RhLXNlY3VyZS1tZWRpYS1zdGFjay5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbImN0YS1zZWN1cmUtbWVkaWEtc3RhY2sudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsNkNBdUJxQjtBQUVyQiwrRUFBK0Y7QUFDL0YscUVBQStEO0FBTy9ELE1BQWEsbUJBQW9CLFNBQVEsbUJBQUs7SUFNNUMsWUFBWSxLQUFnQixFQUFFLEVBQVUsRUFBRSxRQUFrQyxFQUFFO1FBQzVFLEtBQUssQ0FBQyxLQUFLLEVBQUUsRUFBRSxFQUFFLEtBQUssQ0FBQyxDQUFDO1FBRXhCLE1BQU0sVUFBVSxHQUFHLElBQUksMEJBQVksQ0FBQyxJQUFJLEVBQUUsWUFBWSxFQUFFO1lBQ3RELElBQUksRUFBRSxRQUFRO1lBQ2QsT0FBTyxFQUFFLE1BQU07WUFDZixhQUFhLEVBQUUsQ0FBQyxNQUFNLEVBQUUsT0FBTyxDQUFDO1lBQ2hDLFdBQVcsRUFBRSxxQkFBcUI7U0FDbkMsQ0FBQyxDQUFDO1FBRUgsTUFBTSxZQUFZLEdBQUcsSUFBSSwwQkFBWSxDQUFDLElBQUksRUFBRSxjQUFjLEVBQUU7WUFDMUQsSUFBSSxFQUFFLFFBQVE7WUFDZCxPQUFPLEVBQUUsdUJBQXVCO1lBQ2hDLGFBQWEsRUFBRSxDQUFDLHNCQUFzQixFQUFFLHVCQUF1QixDQUFDO1lBQ2hFLFdBQVcsRUFBRSwrQkFBK0I7U0FDN0MsQ0FBQyxDQUFDO1FBRUgsTUFBTSxNQUFNLEdBQUcsS0FBSyxDQUFDLE1BQU0sSUFBSTtZQUM3QixJQUFJLEVBQUU7Z0JBQ0osVUFBVSxFQUFFLFVBQVUsQ0FBQyxhQUFhLEtBQUssTUFBTTthQUNoRDtZQUNELE9BQU8sRUFBRTtnQkFDUCxLQUFLLEVBQUUsWUFBWSxDQUFDLGFBQWE7YUFDbEM7U0FDRixDQUFDO1FBRUYsa0JBQWtCO1FBQ2xCLE1BQU0sYUFBYSxHQUFHLElBQUksZ0NBQWMsQ0FBQyxNQUFNLENBQUMsSUFBSSxFQUFFLFFBQVEsRUFBRTtZQUM5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LFdBQVcsRUFBRSw2Q0FBNkM7U0FDM0QsQ0FBQyxDQUFDO0lBQ0wsQ0FBQztJQUVPLGlCQUFpQixDQUFDLElBQVk7UUFDcEMsTUFBTSxLQUFLLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDO1FBQzNDLElBQUksQ0FBQyxLQUFLO1lBQUUsT0FBTyxzQkFBUSxDQUFDLElBQUksQ0FBQyxFQUFFLENBQUMsQ0FBQztRQUNyQyxNQUFNLEtBQUssR0FBRyxRQUFRLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7UUFDakMsUUFBUSxLQUFLLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQztZQUNqQixLQUFLLEdBQUcsQ0FBQyxDQUFDLE9BQU8sc0JBQVEsQ0FBQyxPQUFPLENBQUMsS0FBSyxDQUFDLENBQUM7WUFDekMsS0FBSyxHQUFHLENBQUMsQ0FBQyxPQUFPLHNCQUFRLENBQUMsS0FBSyxDQUFDLEtBQUssQ0FBQyxDQUFDO1lBQ3ZDLEtBQUssR0FBRyxDQUFDLENBQUMsT0FBTyxzQkFBUSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUN0QyxPQUFPLENBQUMsQ0FBQyxPQUFPLHNCQUFRLENBQUMsSUFBSSxDQUFDLEVBQUUsQ0FBQyxDQUFDO1FBQ3BDLENBQUM7SUFDSCxDQUFDO0NBQ0Y7QUE1ZUQsa0RBNGVDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHtcbiAgU3RhY2ssXG4gIFN0YWNrUHJvcHMsXG4gIEF3cyxcbiAgUmVtb3ZhbFBvbGljeSxcbiAgRHVyYXRpb24sXG4gIENmbk91dHB1dCxcbiAgQ2ZuUGFyYW1ldGVyLFxuICBDdXN0b21SZXNvdXJjZSxcbiAgYXdzX2Nsb3VkZnJvbnQgYXMgY2xvdWRmcm9udCxcbiAgYXdzX2xhbWJkYSBhcyBsYW1iZGEsXG4gIGF3c19hcGlnYXRld2F5IGFzIGFwaWdhdGV3YXksXG4gIGF3c19zZWNyZXRzbWFuYWdlciBhcyBzZWNyZXRzbWFuYWdlcixcbiAgYXdzX3MzIGFzIHMzLFxuICBhd3NfczNfZGVwbG95bWVudCBhcyBzM2RlcGxveSxcbiAgYXdzX2lhbSBhcyBpYW0sXG4gIGF3c19zdGVwZnVuY3Rpb25zIGFzIHNmbixcbiAgYXdzX3N0ZXBmdW5jdGlvbnNfdGFza3MgYXMgdGFza3MsXG4gIGF3c19ldmVudHMgYXMgZXZlbnRzLFxuICBhd3NfZXZlbnRzX3RhcmdldHMgYXMgdGFyZ2V0cyxcbiAgYXdzX2tpbmVzaXMgYXMga2luZXNpcyxcbiAgYXdzX3dhZnYyIGFzIHdhZnYyLFxuICBjdXN0b21fcmVzb3VyY2VzLFxufSBmcm9tIFwiYXdzLWNkay1saWJcIjtcblxuaW1wb3J0IHsgSHR0cE9yaWdpbiwgUmVzdEFwaU9yaWdpbiwgUzNCdWNrZXRPcmlnaW4gfSBmcm9tIFwiYXdzLWNkay1saWIvYXdzLWNsb3VkZnJvbnQtb3JpZ2luc1wiO1xuaW1wb3J0IHsgTm9kZWpzRnVuY3Rpb24gfSBmcm9tIFwiYXdzLWNkay1saWIvYXdzLWxhbWJkYS1ub2RlanNcIjtcbmltcG9ydCB7IENvbnN0cnVjdCB9IGZyb20gXCJjb25zdHJ1Y3RzXCI7XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ1RBU2VjdXJlTWVkaWFTdGFja1Byb3BzIGV4dGVuZHMgU3RhY2tQcm9wcyB7XG4gIHJlYWRvbmx5IGNvbmZpZz86IGFueTtcbn1cblxuZXhwb3J0IGNsYXNzIENUQVNlY3VyZU1lZGlhU3RhY2sgZXh0ZW5kcyBTdGFjayB7XG4gIHB1YmxpYyByZWFkb25seSBrdlN0b3JlOiBjbG91ZGZyb250LktleVZhbHVlU3RvcmU7XG4gIHB1YmxpYyByZWFkb25seSBkaXN0cmlidXRpb246IGNsb3VkZnJvbnQuRGlzdHJpYnV0aW9uO1xuICBwdWJsaWMgcmVhZG9ubHkgZGVtb0J1Y2tldDogczMuQnVja2V0O1xuICBwdWJsaWMgcmVhZG9ubHkgbG9nU3RyZWFtOiBraW5lc2lzLlN0cmVhbTtcbiAgXG4gIGNvbnN0cnVjdG9yKHNjb3BlOiBDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIHByb3BzOiBDVEFTZWN1cmVNZWRpYVN0YWNrUHJvcHMgPSB7fSkge1xuICAgIHN1cGVyKHNjb3BlLCBpZCwgcHJvcHMpO1xuXG4gICAgY29uc3QgZW5hYmxlRGVtbyA9IG5ldyBDZm5QYXJhbWV0ZXIodGhpcywgXCJFbmFibGVEZW1vXCIsIHtcbiAgICAgIHR5cGU6IFwiU3RyaW5nXCIsXG4gICAgICBkZWZhdWx0OiBcInRydWVcIixcbiAgICAgIGFsbG93ZWRWYWx1ZXM6IFtcInRydWVcIiwgXCJmYWxzZVwiXSxcbiAgICAgIGRlc2NyaXB0aW9uOiBcIkRlcGxveSBkZW1vIHdlYnNpdGVcIixcbiAgICB9KTtcblxuICAgIGNvbnN0IGJlZHJvY2tNb2RlbCA9IG5ldyBDZm5QYXJhbWV0ZXIodGhpcywgXCJCZWRyb2NrTW9kZWxcIiwge1xuICAgICAgdHlwZTogXCJTdHJpbmdcIixcbiAgICAgIGRlZmF1bHQ6IFwiYW1hem9uLm5vdmEtbGl0ZS12MTowXCIsXG4gICAgICBhbGxvd2VkVmFsdWVzOiBbXCJhbWF6b24ubm92YS1wcm8tdjE6MFwiLCBcImFtYXpvbi5ub3ZhLWxpdGUtdjE6MFwiXSxcbiAgICAgIGRlc2NyaXB0aW9uOiBcIkJlZHJvY2sgbW9kZWwgZm9yIEFJIGFuYWx5c2lzXCIsXG4gICAgfSk7XG5cbiAgICBjb25zdCBjb25maWcgPSBwcm9wcy5jb25maWcgfHwge1xuICAgICAgbWFpbjoge1xuICAgICAgICBlbmFibGVEZW1vOiBlbmFibGVEZW1vLnZhbHVlQXNTdHJpbmcgPT09IFwidHJ1ZVwiLFxuICAgICAgfSxcbiAgICAgIGJlZHJvY2s6IHtcbiAgICAgICAgbW9kZWw6IGJlZHJvY2tNb2RlbC52YWx1ZUFzU3RyaW5nLFxuICAgICAgfVxuICAgIH07XG5cbiAgICAvLyBDVEEgc2lnbmluZyBrZXlcbiAgICBjb25zdCBzaWduaW5nU2VjcmV0ID0gbmV3IHNlY3JldHNtYW5hZ2VyLlNlY3JldCh0aGlzLCBcIkNUQUtleVwiLCB7XG4gICAgICBnZW5lcmF0ZVNlY3JldFN0cmluZzoge1xuICAgICAgICBzZWNyZXRTdHJpbmdUZW1wbGF0ZTogJ3tcImFsZ29yaXRobVwiOlwiSE1BQy1TSEEyNTZcIn0nLFxuICAgICAgICBnZW5lcmF0ZVN0cmluZ0tleTogXCJzaWduaW5nS2V5XCIsXG4gICAgICAgIHBhc3N3b3JkTGVuZ3RoOiA2NCxcbiAgICAgIH0sXG4gICAgICByZW1vdmFsUG9saWN5OiBSZW1vdmFsUG9saWN5LkRFU1RST1ksXG4gICAgfSk7XG5cbiAgICAvLyBDbG91ZEZyb250IEtleVZhbHVlU3RvcmUgZm9yIHJldm9jYXRpb25cbiAgICB0aGlzLmt2U3RvcmUgPSBuZXcgY2xvdWRmcm9udC5LZXlWYWx1ZVN0b3JlKHRoaXMsIFwiQ1RBUmV2b2NhdGlvblN0b3JlXCIsIHtcbiAgICAgIGNvbW1lbnQ6IFwiQ1RBIHRva2VuIHJldm9jYXRpb24gbGlzdFwiLFxuICAgIH0pO1xuXG4gICAgLy8gQ1RBIHZhbGlkYXRvciBmdW5jdGlvbi5cbiAgICAvL1xuICAgIC8vIEV4cGxpY2l0IGFkZERlcGVuZGVuY3kgb24gdGhlIEtWUzogQ2xvdWRGcm9udCBLZXlWYWx1ZVN0b3JlIGlzIGFcbiAgICAvLyB0d28tcGhhc2UgQVdTIHJlc291cmNlIChQcm92aXNpb25pbmcgLT4gUmVhZHkpLiBUaGUgTDIgY29uc3RydWN0XG4gICAgLy8gcmV0dXJucyB0aGUgQVJOIGJlZm9yZSB0aGUgc3RvcmUgaXMgUmVhZHksIHNvIHdpdGhvdXQgdGhpc1xuICAgIC8vIGRlcGVuZGVuY3kgQ0RLIGNhbiBvcmRlciB0aGUgQ0YgRnVuY3Rpb24ncyBLZXlWYWx1ZVN0b3JlQXNzb2NpYXRpb25zXG4gICAgLy8gYmVmb3JlIHRoZSBLVlMgaXMgUmVhZHkgYW5kIENsb3VkRm9ybWF0aW9uIGZhaWxzIHdpdGg6XG4gICAgLy8gICBcImNhbm5vdCBiZSBhc3NvY2lhdGVkIGJlZm9yZSB0aGUgcmVzb3VyY2UgaXMgcHJvdmlzaW9uZWRcIlxuICAgIC8vIFRoZSBmYWlsdXJlIGlzIGludGVybWl0dGVudCDigJQgaXQgZGVwZW5kcyBvbiBDREsncyBncmFwaCB0cmF2ZXJzYWxcbiAgICAvLyBvcmRlciDigJQgd2hpY2ggbWFrZXMgaXQgZXNwZWNpYWxseSBmcnVzdHJhdGluZyB0byBkZWJ1ZyBvbiBhIGZyZXNoXG4gICAgLy8gZGVwbG95LlxuICAgIGNvbnN0IHZhbGlkYXRvciA9IG5ldyBjbG91ZGZyb250LkZ1bmN0aW9uKHRoaXMsIFwiQ1RBVmFsaWRhdG9yXCIsIHtcbiAgICAgIGNvZGU6IGNsb3VkZnJvbnQuRnVuY3Rpb25Db2RlLmZyb21GaWxlKHsgZmlsZVBhdGg6IFwibGFtYmRhL2N0YV90b2tlbl92YWxpZGF0b3IuanNcIiB9KSxcbiAgICAgIGZ1bmN0aW9uTmFtZTogYCR7QXdzLlNUQUNLX05BTUV9LUNUQS1WYWxpZGF0b3JgLFxuICAgICAgcnVudGltZTogY2xvdWRmcm9udC5GdW5jdGlvblJ1bnRpbWUuSlNfMl8wLFxuICAgICAga2V5VmFsdWVTdG9yZTogdGhpcy5rdlN0b3JlLFxuICAgIH0pO1xuICAgIHZhbGlkYXRvci5ub2RlLmFkZERlcGVuZGVuY3kodGhpcy5rdlN0b3JlKTtcblxuICAgIC8vIFRva2VuIGdlbmVyYXRvciAoTm9kZSBTREspXG4gICAgLy8gTm9kZWpzRnVuY3Rpb24gKGVzYnVpbGQpIGJ1bmRsZXMgdGhlIGhhbmRsZXIgdG9nZXRoZXIgd2l0aCBpdHNcbiAgICAvLyB0aGlyZC1wYXJ0eSBkZXBlbmRlbmN5IGNib3IteCwgd2hpY2ggaXMgTk9UIHByb3ZpZGVkIGJ5IHRoZSBMYW1iZGFcbiAgICAvLyBOb2RlLmpzIHJ1bnRpbWUuIEEgcGxhaW4gQ29kZS5mcm9tQXNzZXQoXCJsYW1iZGFcIikgc2hpcHMgbm8gbm9kZV9tb2R1bGVzLFxuICAgIC8vIHNvIHJlcXVpcmUoJ2Nib3IteCcpIGZhaWxzIGF0IG1vZHVsZSBpbml0IGFuZCBBUEkgR2F0ZXdheSByZXR1cm5zIGEgNTAyXG4gICAgLy8gd2l0aCBubyBDT1JTIGhlYWRlcnMg4oCUIHN1cmZhY2luZyBpbiB0aGUgYnJvd3NlciBhcyBhIENPUlMgZXJyb3IuXG4gICAgLy8gVGhlIEFXUyBTREsgdjMgcGFja2FnZXMgKEBhd3Mtc2RrLyopIHJlbWFpbiBleHRlcm5hbGl6ZWQgYnkgZGVmYXVsdFxuICAgIC8vIHNpbmNlIHRoZXkgQVJFIHByZXNlbnQgaW4gdGhlIHJ1bnRpbWUuXG4gICAgY29uc3QgZ2VuZXJhdG9yID0gbmV3IE5vZGVqc0Z1bmN0aW9uKHRoaXMsIFwiQ1RBR2VuZXJhdG9yXCIsIHtcbiAgICAgIHJ1bnRpbWU6IGxhbWJkYS5SdW50aW1lLk5PREVKU18yMl9YLFxuICAgICAgZW50cnk6IFwibGFtYmRhL2N0YV90b2tlbl9nZW5lcmF0b3IuanNcIixcbiAgICAgIGhhbmRsZXI6IFwiaGFuZGxlclwiLFxuICAgICAgdGltZW91dDogRHVyYXRpb24uc2Vjb25kcygxMCksXG4gICAgICBlbnZpcm9ubWVudDogeyBTRUNSRVRfTkFNRTogc2lnbmluZ1NlY3JldC5zZWNyZXROYW1lIH0sXG4gICAgfSk7XG5cbiAgICAvLyBUb2tlbiBnZW5lcmF0b3IgKFB5dGhvbiBTREspXG4gICAgY29uc3QgZ2VuZXJhdG9yUHl0aG9uID0gbmV3IGxhbWJkYS5GdW5jdGlvbih0aGlzLCBcIkNUQUdlbmVyYXRvclB5dGhvblwiLCB7XG4gICAgICBydW50aW1lOiBsYW1iZGEuUnVudGltZS5QWVRIT05fM18xMyxcbiAgICAgIGhhbmRsZXI6IFwiaGFuZGxlci5oYW5kbGVyXCIsXG4gICAgICBjb2RlOiBsYW1iZGEuQ29kZS5mcm9tQXNzZXQoXCJsYW1iZGEtcHl0aG9uXCIpLFxuICAgICAgdGltZW91dDogRHVyYXRpb24uc2Vjb25kcygxMCksXG4gICAgICBlbnZpcm9ubWVudDogeyBTRUNSRVRfTkFNRTogc2lnbmluZ1NlY3JldC5zZWNyZXROYW1lIH0sXG4gICAgfSk7XG5cbiAgICAvLyBUb2tlbiBnZW5lcmF0b3IgKFJ1YnkgU0RLKVxuICAgIGNvbnN0IGdlbmVyYXRvclJ1YnkgPSBuZXcgbGFtYmRhLkZ1bmN0aW9uKHRoaXMsIFwiQ1RBR2VuZXJhdG9yUnVieVwiLCB7XG4gICAgICBydW50aW1lOiBsYW1iZGEuUnVudGltZS5SVUJZXzNfMyxcbiAgICAgIGhhbmRsZXI6IFwiaGFuZGxlci5oYW5kbGVyXCIsXG4gICAgICBjb2RlOiBsYW1iZGEuQ29kZS5mcm9tQXNzZXQoXCJsYW1iZGEtcnVieVwiKSxcbiAgICAgIHRpbWVvdXQ6IER1cmF0aW9uLnNlY29uZHMoMTApLFxuICAgICAgZW52aXJvbm1lbnQ6IHsgU0VDUkVUX05BTUU6IHNpZ25pbmdTZWNyZXQuc2VjcmV0TmFtZSB9LFxuICAgIH0pO1xuXG4gICAgLy8gVG9rZW4gcmV2b2NhdGlvbiBoYW5kbGVyXG4gICAgY29uc3QgcmV2b2tlciA9IG5ldyBsYW1iZGEuRnVuY3Rpb24odGhpcywgXCJDVEFSZXZva2VyXCIsIHtcbiAgICAgIHJ1bnRpbWU6IGxhbWJkYS5SdW50aW1lLk5PREVKU18yMl9YLFxuICAgICAgaGFuZGxlcjogXCJjdGFfcmV2b2NhdGlvbi5oYW5kbGVyXCIsXG4gICAgICBjb2RlOiBsYW1iZGEuQ29kZS5mcm9tQXNzZXQoXCJsYW1iZGFcIiksXG4gICAgICB0aW1lb3V0OiBEdXJhdGlvbi5zZWNvbmRzKDEwKSxcbiAgICAgIGVudmlyb25tZW50OiB7IEtWU19BUk46IHRoaXMua3ZTdG9yZS5rZXlWYWx1ZVN0b3JlQXJuIH0sXG4gICAgfSk7XG5cbiAgICBzaWduaW5nU2VjcmV0LmdyYW50UmVhZChnZW5lcmF0b3IpO1xuICAgIHNpZ25pbmdTZWNyZXQuZ3JhbnRSZWFkKGdlbmVyYXRvclB5dGhvbik7XG4gICAgc2lnbmluZ1NlY3JldC5ncmFudFJlYWQoZ2VuZXJhdG9yUnVieSk7XG5cbiAgICAvLyBHcmFudCBLVlMgdXBkYXRlIHBlcm1pc3Npb24gdmlhIElBTSBwb2xpY3lcbiAgICByZXZva2VyLmFkZFRvUm9sZVBvbGljeShuZXcgaWFtLlBvbGljeVN0YXRlbWVudCh7XG4gICAgICBlZmZlY3Q6IGlhbS5FZmZlY3QuQUxMT1csXG4gICAgICBhY3Rpb25zOiBbXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6UHV0S2V5XCIsIFwiY2xvdWRmcm9udC1rZXl2YWx1ZXN0b3JlOkRlc2NyaWJlS2V5VmFsdWVTdG9yZVwiXSxcbiAgICAgIHJlc291cmNlczogW3RoaXMua3ZTdG9yZS5rZXlWYWx1ZVN0b3JlQXJuXSxcbiAgICB9KSk7XG5cbiAgICAvLyAtLS0gS2V5IHN5bmMgTGFtYmRhIChjdXN0b20gcmVzb3VyY2UgKyByb3RhdGlvbikgLS0tXG4gICAgY29uc3Qgc3luY0tleXNUb0t2cyA9IG5ldyBsYW1iZGEuRnVuY3Rpb24odGhpcywgXCJTeW5jS2V5c1RvS3ZzXCIsIHtcbiAgICAgIHJ1bnRpbWU6IGxhbWJkYS5SdW50aW1lLk5PREVKU18yMl9YLFxuICAgICAgaGFuZGxlcjogXCJpbmRleC5oYW5kbGVyXCIsXG4gICAgICBjb2RlOiBsYW1iZGEuQ29kZS5mcm9tQXNzZXQoXCJsYW1iZGEvc3luY19rZXlzXCIpLFxuICAgICAgdGltZW91dDogRHVyYXRpb24uc2Vjb25kcygzMCksXG4gICAgICBlbnZpcm9ubWVudDoge1xuICAgICAgICBTRUNSRVRfTkFNRTogc2lnbmluZ1NlY3JldC5zZWNyZXROYW1lLFxuICAgICAgICBLVlNfQVJOOiB0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUFybixcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICBzaWduaW5nU2VjcmV0LmdyYW50UmVhZChzeW5jS2V5c1RvS3ZzKTtcbiAgICBzaWduaW5nU2VjcmV0LmdyYW50V3JpdGUoc3luY0tleXNUb0t2cyk7XG4gICAgc3luY0tleXNUb0t2cy5hZGRUb1JvbGVQb2xpY3kobmV3IGlhbS5Qb2xpY3lTdGF0ZW1lbnQoe1xuICAgICAgZWZmZWN0OiBpYW0uRWZmZWN0LkFMTE9XLFxuICAgICAgYWN0aW9uczogW1xuICAgICAgICBcImNsb3VkZnJvbnQta2V5dmFsdWVzdG9yZTpQdXRLZXlcIixcbiAgICAgICAgXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6RGVzY3JpYmVLZXlWYWx1ZVN0b3JlXCIsXG4gICAgICBdLFxuICAgICAgcmVzb3VyY2VzOiBbdGhpcy5rdlN0b3JlLmtleVZhbHVlU3RvcmVBcm5dLFxuICAgIH0pKTtcblxuICAgIC8vIEN1c3RvbSByZXNvdXJjZTogc3luYyBrZXkgdG8gS1ZTIG9uIGRlcGxveVxuICAgIGNvbnN0IGtleVN5bmNQcm92aWRlciA9IG5ldyBjdXN0b21fcmVzb3VyY2VzLlByb3ZpZGVyKHRoaXMsIFwiS2V5U3luY1Byb3ZpZGVyXCIsIHtcbiAgICAgIG9uRXZlbnRIYW5kbGVyOiBzeW5jS2V5c1RvS3ZzLFxuICAgIH0pO1xuXG4gICAgbmV3IEN1c3RvbVJlc291cmNlKHRoaXMsIFwiS2V5U3luY1Jlc291cmNlXCIsIHtcbiAgICAgIHNlcnZpY2VUb2tlbjoga2V5U3luY1Byb3ZpZGVyLnNlcnZpY2VUb2tlbixcbiAgICAgIHByb3BlcnRpZXM6IHtcbiAgICAgICAgLy8gRm9yY2UgdXBkYXRlIG9uIGVhY2ggZGVwbG95IHRvIGVuc3VyZSBrZXkgaXMgc3luY2VkXG4gICAgICAgIFRpbWVzdGFtcDogRGF0ZS5ub3coKS50b1N0cmluZygpLFxuICAgICAgfSxcbiAgICB9KTtcblxuICAgIC8vIC0tLSBLZXkgcm90YXRpb24gd29ya2Zsb3cgLS0tXG4gICAgY29uc3Qgcm90YXRlS2V5VGFzayA9IG5ldyB0YXNrcy5MYW1iZGFJbnZva2UodGhpcywgXCJSb3RhdGVTaWduaW5nS2V5XCIsIHtcbiAgICAgIGxhbWJkYUZ1bmN0aW9uOiBzeW5jS2V5c1RvS3ZzLFxuICAgICAgcGF5bG9hZDogc2ZuLlRhc2tJbnB1dC5mcm9tT2JqZWN0KHsgcm90YXRlOiB0cnVlIH0pLFxuICAgICAgcmVzdWx0UGF0aDogc2ZuLkpzb25QYXRoLkRJU0NBUkQsXG4gICAgfSk7XG5cbiAgICBjb25zdCByb3RhdGlvbldvcmtmbG93ID0gbmV3IHNmbi5TdGF0ZU1hY2hpbmUodGhpcywgXCJLZXlSb3RhdGlvbldvcmtmbG93XCIsIHtcbiAgICAgIHN0YXRlTWFjaGluZU5hbWU6IGAke0F3cy5TVEFDS19OQU1FfV9Sb3RhdGVLZXlzYCxcbiAgICAgIGRlZmluaXRpb25Cb2R5OiBzZm4uRGVmaW5pdGlvbkJvZHkuZnJvbUNoYWluYWJsZShyb3RhdGVLZXlUYXNrKSxcbiAgICAgIHRpbWVvdXQ6IER1cmF0aW9uLm1pbnV0ZXMoNSksXG4gICAgfSk7XG5cbiAgICAvLyBSb3RhdGUga2V5cyBtb250aGx5IGJ5IGRlZmF1bHRcbiAgICBjb25zdCByb3RhdGlvblNjaGVkdWxlID0gY29uZmlnLm1haW4ucm90YXRpb25GcmVxdWVuY3kgfHwgXCIzMGRcIjtcbiAgICBjb25zdCByb3RhdGlvblJhdGUgPSB0aGlzLnBhcnNlUm90YXRpb25SYXRlKHJvdGF0aW9uU2NoZWR1bGUpO1xuICAgIG5ldyBldmVudHMuUnVsZSh0aGlzLCBcIktleVJvdGF0aW9uU2NoZWR1bGVcIiwge1xuICAgICAgc2NoZWR1bGU6IGV2ZW50cy5TY2hlZHVsZS5yYXRlKHJvdGF0aW9uUmF0ZSksXG4gICAgICB0YXJnZXRzOiBbbmV3IHRhcmdldHMuU2ZuU3RhdGVNYWNoaW5lKHJvdGF0aW9uV29ya2Zsb3cpXSxcbiAgICB9KTtcblxuICAgIC8vIEFQSSBHYXRld2F5XG4gICAgY29uc3QgYXBpID0gbmV3IGFwaWdhdGV3YXkuUmVzdEFwaSh0aGlzLCBcIkNUQUFQSVwiLCB7XG4gICAgICByZXN0QXBpTmFtZTogXCJDVEEgVG9rZW4gQVBJXCIsXG4gICAgICBkZWZhdWx0Q29yc1ByZWZsaWdodE9wdGlvbnM6IHtcbiAgICAgICAgYWxsb3dPcmlnaW5zOiBhcGlnYXRld2F5LkNvcnMuQUxMX09SSUdJTlMsXG4gICAgICAgIGFsbG93TWV0aG9kczogYXBpZ2F0ZXdheS5Db3JzLkFMTF9NRVRIT0RTLFxuICAgICAgfSxcbiAgICB9KTtcblxuICAgIC8vIEF0dGFjaCBDT1JTIGhlYWRlcnMgdG8gQVBJIEdhdGV3YXkncyBkZWZhdWx0IGdhdGV3YXkgcmVzcG9uc2VzIHNvIHRoYXRcbiAgICAvLyBpbnRlZ3JhdGlvbiBlcnJvcnMgKGUuZy4gYSBMYW1iZGEgNXh4L3RpbWVvdXQsIG9yIGEgNHh4KSBzdGlsbCBjYXJyeVxuICAgIC8vIEFjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpbi4gV2l0aG91dCB0aGlzLCBhbiBlcnJvcmVkIHJlcXVlc3QgcmV0dXJucyBhXG4gICAgLy8gcmVzcG9uc2Ugd2l0aCBubyBDT1JTIGhlYWRlciwgd2hpY2ggYnJvd3NlcnMgc3VyZmFjZSBhcyBhIG1pc2xlYWRpbmdcbiAgICAvLyBcImJsb2NrZWQgYnkgQ09SUyBwb2xpY3lcIiBlcnJvciB0aGF0IG1hc2tzIHRoZSByZWFsIHN0YXR1cyBjb2RlLlxuICAgIGNvbnN0IGNvcnNSZXNwb25zZUhlYWRlcnMgPSB7XG4gICAgICBcIkFjY2Vzcy1Db250cm9sLUFsbG93LU9yaWdpblwiOiBcIicqJ1wiLFxuICAgICAgXCJBY2Nlc3MtQ29udHJvbC1BbGxvdy1IZWFkZXJzXCI6IFwiJyonXCIsXG4gICAgfTtcbiAgICBhcGkuYWRkR2F0ZXdheVJlc3BvbnNlKFwiRGVmYXVsdDRYWFwiLCB7XG4gICAgICB0eXBlOiBhcGlnYXRld2F5LlJlc3BvbnNlVHlwZS5ERUZBVUxUXzRYWCxcbiAgICAgIHJlc3BvbnNlSGVhZGVyczogY29yc1Jlc3BvbnNlSGVhZGVycyxcbiAgICB9KTtcbiAgICBhcGkuYWRkR2F0ZXdheVJlc3BvbnNlKFwiRGVmYXVsdDVYWFwiLCB7XG4gICAgICB0eXBlOiBhcGlnYXRld2F5LlJlc3BvbnNlVHlwZS5ERUZBVUxUXzVYWCxcbiAgICAgIHJlc3BvbnNlSGVhZGVyczogY29yc1Jlc3BvbnNlSGVhZGVycyxcbiAgICB9KTtcblxuICAgIGNvbnN0IHRva2VuUmVzb3VyY2UgPSBhcGkucm9vdC5hZGRSZXNvdXJjZShcInRva2VuXCIpO1xuICAgIHRva2VuUmVzb3VyY2UuYWRkTWV0aG9kKFwiUE9TVFwiLCBuZXcgYXBpZ2F0ZXdheS5MYW1iZGFJbnRlZ3JhdGlvbihnZW5lcmF0b3IpKTtcblxuICAgIGNvbnN0IHRva2VuUHl0aG9uUmVzb3VyY2UgPSBhcGkucm9vdC5hZGRSZXNvdXJjZShcInRva2VuLXB5dGhvblwiKTtcbiAgICB0b2tlblB5dGhvblJlc291cmNlLmFkZE1ldGhvZChcIlBPU1RcIiwgbmV3IGFwaWdhdGV3YXkuTGFtYmRhSW50ZWdyYXRpb24oZ2VuZXJhdG9yUHl0aG9uKSk7XG5cbiAgICBjb25zdCB0b2tlblJ1YnlSZXNvdXJjZSA9IGFwaS5yb290LmFkZFJlc291cmNlKFwidG9rZW4tcnVieVwiKTtcbiAgICB0b2tlblJ1YnlSZXNvdXJjZS5hZGRNZXRob2QoXCJQT1NUXCIsIG5ldyBhcGlnYXRld2F5LkxhbWJkYUludGVncmF0aW9uKGdlbmVyYXRvclJ1YnkpKTtcbiAgICBcbiAgICBjb25zdCByZXZva2VSZXNvdXJjZSA9IGFwaS5yb290LmFkZFJlc291cmNlKFwicmV2b2tlXCIpO1xuICAgIHJldm9rZVJlc291cmNlLmFkZE1ldGhvZChcIlBPU1RcIiwgbmV3IGFwaWdhdGV3YXkuTGFtYmRhSW50ZWdyYXRpb24ocmV2b2tlcikpO1xuXG4gICAgLy8gV0FGdjIgV2ViIEFDTCDigJQgcmF0ZS1saW1pdCBQT1NUIC9hcGkvdG9rZW4gcGVyIHNvdXJjZSBJUC5cbiAgICAvLzogYXV0b21hdGVkLXNjcmFwaW5nIG1pdGlnYXRpb24uIFJhdGUtYmFzZWQgcnVsZXMgdXNlIGFcbiAgICAvLyByb2xsaW5nIDUtbWludXRlIHdpbmRvdzsgMzAwIHJlcS81bWluIOKJiCA2MCByZXEvbWluIHBlciBJUCwgd2VsbFxuICAgIC8vIGFib3ZlIGxlZ2l0aW1hdGUgcGxheWVyIHRyYWZmaWMgKG1pbnQgb25jZSDihpIgMmggVFRMIOKGkiBuZXh0IG1pbnQpXG4gICAgLy8gYnV0IHRpZ2h0IGVub3VnaCB0byBzdG9wIGEgbWludC15b3VyLW93bi10b2tlbiBzY3JhcGVyLlxuICAgIC8vIEJsb2NrZWQgcmVxdWVzdHMgZ2V0IGEgY3VzdG9tIDQyOSByZXNwb25zZSBpbnN0ZWFkIG9mIHRoZSBkZWZhdWx0IDQwMy5cbiAgICBjb25zdCByYXRlTGltaXRCb2R5ID0gXCJDVEFXZWJBY2xSYXRlTGltaXQ0MjlcIjtcbiAgICBjb25zdCB3ZWJBY2wgPSBuZXcgd2FmdjIuQ2ZuV2ViQUNMKHRoaXMsIFwiQ1RBV2ViQWNsXCIsIHtcbiAgICAgIG5hbWU6IGAke0F3cy5TVEFDS19OQU1FfS10b2tlbi1yYXRlLWxpbWl0YCxcbiAgICAgIGRlc2NyaXB0aW9uOiBcIlJhdGUtbGltaXQgUE9TVCAvYXBpL3Rva2VuIHRvIG1pdGlnYXRlIGF1dG9tYXRlZCBDV1QgbWludGluZ1wiLFxuICAgICAgc2NvcGU6IFwiQ0xPVURGUk9OVFwiLFxuICAgICAgZGVmYXVsdEFjdGlvbjogeyBhbGxvdzoge30gfSxcbiAgICAgIHZpc2liaWxpdHlDb25maWc6IHtcbiAgICAgICAgY2xvdWRXYXRjaE1ldHJpY3NFbmFibGVkOiB0cnVlLFxuICAgICAgICBtZXRyaWNOYW1lOiBgJHtBd3MuU1RBQ0tfTkFNRX0td2ViLWFjbGAsXG4gICAgICAgIHNhbXBsZWRSZXF1ZXN0c0VuYWJsZWQ6IHRydWUsXG4gICAgICB9LFxuICAgICAgY3VzdG9tUmVzcG9uc2VCb2RpZXM6IHtcbiAgICAgICAgW3JhdGVMaW1pdEJvZHldOiB7XG4gICAgICAgICAgY29udGVudFR5cGU6IFwiQVBQTElDQVRJT05fSlNPTlwiLFxuICAgICAgICAgIGNvbnRlbnQ6IEpTT04uc3RyaW5naWZ5KHsgZXJyb3I6IFwicmF0ZV9saW1pdGVkXCIsIG1lc3NhZ2U6IFwiVG9vIG1hbnkgdG9rZW4gbWludCByZXF1ZXN0cyBmcm9tIHRoaXMgSVA7IHRyeSBhZ2FpbiBpbiBhIGZldyBtaW51dGVzLlwiIH0pLFxuICAgICAgICB9LFxuICAgICAgfSxcbiAgICAgIHJ1bGVzOiBbe1xuICAgICAgICBuYW1lOiBcIlRva2VuTWludFJhdGVMaW1pdFwiLFxuICAgICAgICBwcmlvcml0eTogMCxcbiAgICAgICAgYWN0aW9uOiB7XG4gICAgICAgICAgYmxvY2s6IHtcbiAgICAgICAgICAgIGN1c3RvbVJlc3BvbnNlOiB7XG4gICAgICAgICAgICAgIHJlc3BvbnNlQ29kZTogNDI5LFxuICAgICAgICAgICAgICBjdXN0b21SZXNwb25zZUJvZHlLZXk6IHJhdGVMaW1pdEJvZHksXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIHN0YXRlbWVudDoge1xuICAgICAgICAgIHJhdGVCYXNlZFN0YXRlbWVudDoge1xuICAgICAgICAgICAgbGltaXQ6IDMwMCxcbiAgICAgICAgICAgIGFnZ3JlZ2F0ZUtleVR5cGU6IFwiSVBcIixcbiAgICAgICAgICAgIHNjb3BlRG93blN0YXRlbWVudDoge1xuICAgICAgICAgICAgICBieXRlTWF0Y2hTdGF0ZW1lbnQ6IHtcbiAgICAgICAgICAgICAgICBmaWVsZFRvTWF0Y2g6IHsgdXJpUGF0aDoge30gfSxcbiAgICAgICAgICAgICAgICBwb3NpdGlvbmFsQ29uc3RyYWludDogXCJTVEFSVFNfV0lUSFwiLFxuICAgICAgICAgICAgICAgIHNlYXJjaFN0cmluZzogXCIvYXBpL3Rva2VuXCIsXG4gICAgICAgICAgICAgICAgdGV4dFRyYW5zZm9ybWF0aW9uczogW3sgcHJpb3JpdHk6IDAsIHR5cGU6IFwiTk9ORVwiIH1dLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICB2aXNpYmlsaXR5Q29uZmlnOiB7XG4gICAgICAgICAgY2xvdWRXYXRjaE1ldHJpY3NFbmFibGVkOiB0cnVlLFxuICAgICAgICAgIG1ldHJpY05hbWU6IGAke0F3cy5TVEFDS19OQU1FfS10b2tlbi1yYXRlLWxpbWl0YCxcbiAgICAgICAgICBzYW1wbGVkUmVxdWVzdHNFbmFibGVkOiB0cnVlLFxuICAgICAgICB9LFxuICAgICAgfV0sXG4gICAgfSk7XG5cbiAgICAvLyBEZW1vIHdlYnNpdGUgKGNvbmRpdGlvbmFsKVxuICAgIGxldCBkaXN0cmlidXRpb246IGNsb3VkZnJvbnQuRGlzdHJpYnV0aW9uO1xuICAgIGxldCBkZW1vQnVja2V0OiBzMy5CdWNrZXQgfCB1bmRlZmluZWQ7XG5cbiAgICBpZiAoY29uZmlnLm1haW4uZW5hYmxlRGVtbykge1xuICAgICAgZGVtb0J1Y2tldCA9IG5ldyBzMy5CdWNrZXQodGhpcywgXCJEZW1vV2Vic2l0ZVwiLCB7XG4gICAgICAgIHJlbW92YWxQb2xpY3k6IFJlbW92YWxQb2xpY3kuREVTVFJPWSxcbiAgICAgICAgYXV0b0RlbGV0ZU9iamVjdHM6IHRydWUsXG4gICAgICB9KTtcblxuICAgICAgbmV3IHMzZGVwbG95LkJ1Y2tldERlcGxveW1lbnQodGhpcywgXCJEZXBsb3lEZW1vU2l0ZVwiLCB7XG4gICAgICAgIHNvdXJjZXM6IFtzM2RlcGxveS5Tb3VyY2UuYXNzZXQoXCJyZXNvdXJjZXMvZGVtby13ZWJzaXRlXCIpXSxcbiAgICAgICAgZGVzdGluYXRpb25CdWNrZXQ6IGRlbW9CdWNrZXQsXG4gICAgICAgIGRlc3RpbmF0aW9uS2V5UHJlZml4OiBcIndlYnNpdGVcIixcbiAgICAgICAgcHJ1bmU6IGZhbHNlLFxuICAgICAgfSk7XG5cbiAgICAgIGRpc3RyaWJ1dGlvbiA9IG5ldyBjbG91ZGZyb250LkRpc3RyaWJ1dGlvbih0aGlzLCBcIkNUQURpc3RyaWJ1dGlvblwiLCB7XG4gICAgICAgIHdlYkFjbElkOiB3ZWJBY2wuYXR0ckFybixcbiAgICAgICAgZGVmYXVsdEJlaGF2aW9yOiB7XG4gICAgICAgICAgb3JpZ2luOiBuZXcgSHR0cE9yaWdpbihcImNkbi5tZWRpYXBsYXlwZW4uY29tXCIpLFxuICAgICAgICAgIHZpZXdlclByb3RvY29sUG9saWN5OiBjbG91ZGZyb250LlZpZXdlclByb3RvY29sUG9saWN5LlJFRElSRUNUX1RPX0hUVFBTLFxuICAgICAgICAgIGNhY2hlUG9saWN5OiBuZXcgY2xvdWRmcm9udC5DYWNoZVBvbGljeSh0aGlzLCBcIkNUQUNhY2hlUG9saWN5XCIsIHtcbiAgICAgICAgICAgIGhlYWRlckJlaGF2aW9yOiBjbG91ZGZyb250LkNhY2hlSGVhZGVyQmVoYXZpb3IuYWxsb3dMaXN0KFxuICAgICAgICAgICAgICBcIkNsb3VkRnJvbnQtVmlld2VyLUNvdW50cnlcIlxuICAgICAgICAgICAgKSxcbiAgICAgICAgICB9KSxcbiAgICAgICAgICByZXNwb25zZUhlYWRlcnNQb2xpY3k6IG5ldyBjbG91ZGZyb250LlJlc3BvbnNlSGVhZGVyc1BvbGljeSh0aGlzLCBcIkNUQUNvcnNSZXNwb25zZVBvbGljeVwiLCB7XG4gICAgICAgICAgICByZXNwb25zZUhlYWRlcnNQb2xpY3lOYW1lOiBgJHtBd3MuU1RBQ0tfTkFNRX0tQ1RBLUNPUlNgLFxuICAgICAgICAgICAgY29yc0JlaGF2aW9yOiB7XG4gICAgICAgICAgICAgIGFjY2Vzc0NvbnRyb2xBbGxvd09yaWdpbnM6IFtcIipcIl0sXG4gICAgICAgICAgICAgIGFjY2Vzc0NvbnRyb2xBbGxvd0hlYWRlcnM6IFtcIkNUQS1Db21tb24tQWNjZXNzLVRva2VuXCIsIFwiQ29udGVudC1UeXBlXCJdLFxuICAgICAgICAgICAgICBhY2Nlc3NDb250cm9sQWxsb3dNZXRob2RzOiBbXCJHRVRcIiwgXCJIRUFEXCIsIFwiT1BUSU9OU1wiXSxcbiAgICAgICAgICAgICAgYWNjZXNzQ29udHJvbEV4cG9zZUhlYWRlcnM6IFtcIkNUQS1Db21tb24tQWNjZXNzLVRva2VuXCJdLFxuICAgICAgICAgICAgICBhY2Nlc3NDb250cm9sQWxsb3dDcmVkZW50aWFsczogZmFsc2UsXG4gICAgICAgICAgICAgIGFjY2Vzc0NvbnRyb2xNYXhBZ2U6IER1cmF0aW9uLmhvdXJzKDI0KSxcbiAgICAgICAgICAgICAgb3JpZ2luT3ZlcnJpZGU6IHRydWUsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0pLFxuICAgICAgICAgIG9yaWdpblJlcXVlc3RQb2xpY3k6IGNsb3VkZnJvbnQuT3JpZ2luUmVxdWVzdFBvbGljeS5BTExfVklFV0VSX0VYQ0VQVF9IT1NUX0hFQURFUixcbiAgICAgICAgICBmdW5jdGlvbkFzc29jaWF0aW9uczogW3tcbiAgICAgICAgICAgIGZ1bmN0aW9uOiB2YWxpZGF0b3IsXG4gICAgICAgICAgICBldmVudFR5cGU6IGNsb3VkZnJvbnQuRnVuY3Rpb25FdmVudFR5cGUuVklFV0VSX1JFUVVFU1QsXG4gICAgICAgICAgfV0sXG4gICAgICAgIH0sXG4gICAgICAgIGFkZGl0aW9uYWxCZWhhdmlvcnM6IHtcbiAgICAgICAgICBcIi9hcGkvKlwiOiB7XG4gICAgICAgICAgICBvcmlnaW46IG5ldyBSZXN0QXBpT3JpZ2luKGFwaSksXG4gICAgICAgICAgICB2aWV3ZXJQcm90b2NvbFBvbGljeTogY2xvdWRmcm9udC5WaWV3ZXJQcm90b2NvbFBvbGljeS5SRURJUkVDVF9UT19IVFRQUyxcbiAgICAgICAgICAgIGFsbG93ZWRNZXRob2RzOiBjbG91ZGZyb250LkFsbG93ZWRNZXRob2RzLkFMTE9XX0FMTCxcbiAgICAgICAgICAgIGNhY2hlUG9saWN5OiBjbG91ZGZyb250LkNhY2hlUG9saWN5LkNBQ0hJTkdfRElTQUJMRUQsXG4gICAgICAgICAgICBvcmlnaW5SZXF1ZXN0UG9saWN5OiBjbG91ZGZyb250Lk9yaWdpblJlcXVlc3RQb2xpY3kuQUxMX1ZJRVdFUl9FWENFUFRfSE9TVF9IRUFERVIsXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcIi93ZWJzaXRlLypcIjoge1xuICAgICAgICAgICAgb3JpZ2luOiBTM0J1Y2tldE9yaWdpbi53aXRoT3JpZ2luQWNjZXNzQ29udHJvbChkZW1vQnVja2V0KSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgfSk7XG5cbiAgICB9IGVsc2Uge1xuICAgICAgZGlzdHJpYnV0aW9uID0gbmV3IGNsb3VkZnJvbnQuRGlzdHJpYnV0aW9uKHRoaXMsIFwiQ1RBRGlzdHJpYnV0aW9uXCIsIHtcbiAgICAgICAgd2ViQWNsSWQ6IHdlYkFjbC5hdHRyQXJuLFxuICAgICAgICBkZWZhdWx0QmVoYXZpb3I6IHtcbiAgICAgICAgICBvcmlnaW46IG5ldyBSZXN0QXBpT3JpZ2luKGFwaSksXG4gICAgICAgICAgZnVuY3Rpb25Bc3NvY2lhdGlvbnM6IFt7XG4gICAgICAgICAgICBmdW5jdGlvbjogdmFsaWRhdG9yLFxuICAgICAgICAgICAgZXZlbnRUeXBlOiBjbG91ZGZyb250LkZ1bmN0aW9uRXZlbnRUeXBlLlZJRVdFUl9SRVFVRVNULFxuICAgICAgICAgIH1dLFxuICAgICAgICB9LFxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgdGhpcy5kaXN0cmlidXRpb24gPSBkaXN0cmlidXRpb247XG4gICAgaWYgKGNvbmZpZy5tYWluLmVuYWJsZURlbW8pIHtcbiAgICAgIHRoaXMuZGVtb0J1Y2tldCA9IGRlbW9CdWNrZXQhO1xuICAgIH1cblxuICAgIC8vIC0tLSBSZWFsLVRpbWUgTG9nZ2luZyB2aWEgS2luZXNpcyAtLS1cbiAgICBjb25zdCBsb2dTdHJlYW0gPSBuZXcga2luZXNpcy5TdHJlYW0odGhpcywgXCJSZWFsdGltZUxvZ1N0cmVhbVwiLCB7XG4gICAgICBzdHJlYW1Nb2RlOiBraW5lc2lzLlN0cmVhbU1vZGUuT05fREVNQU5ELFxuICAgICAgcmV0ZW50aW9uUGVyaW9kOiBEdXJhdGlvbi5ob3VycygyNCksXG4gICAgfSk7XG4gICAgdGhpcy5sb2dTdHJlYW0gPSBsb2dTdHJlYW07XG5cbiAgICBjb25zdCBjZktpbmVzaXNSb2xlID0gbmV3IGlhbS5Sb2xlKHRoaXMsIFwiQ2xvdWRGcm9udEtpbmVzaXNSb2xlXCIsIHtcbiAgICAgIGFzc3VtZWRCeTogbmV3IGlhbS5TZXJ2aWNlUHJpbmNpcGFsKFwiY2xvdWRmcm9udC5hbWF6b25hd3MuY29tXCIpLFxuICAgIH0pO1xuICAgIGxvZ1N0cmVhbS5ncmFudFdyaXRlKGNmS2luZXNpc1JvbGUpO1xuXG4gICAgY29uc3QgcmVhbHRpbWVMb2dDb25maWcgPSBuZXcgY2xvdWRmcm9udC5DZm5SZWFsdGltZUxvZ0NvbmZpZyh0aGlzLCBcIlJlYWx0aW1lTG9nQ29uZmlnXCIsIHtcbiAgICAgIG5hbWU6IGAke0F3cy5TVEFDS19OQU1FfS1yZWFsdGltZS1sb2dzYCxcbiAgICAgIHNhbXBsaW5nUmF0ZTogMTAwLFxuICAgICAgZW5kUG9pbnRzOiBbe1xuICAgICAgICBzdHJlYW1UeXBlOiBcIktpbmVzaXNcIixcbiAgICAgICAga2luZXNpc1N0cmVhbUNvbmZpZzoge1xuICAgICAgICAgIHJvbGVBcm46IGNmS2luZXNpc1JvbGUucm9sZUFybixcbiAgICAgICAgICBzdHJlYW1Bcm46IGxvZ1N0cmVhbS5zdHJlYW1Bcm4sXG4gICAgICAgIH0sXG4gICAgICB9XSxcbiAgICAgIGZpZWxkczogW1xuICAgICAgICBcInRpbWVzdGFtcFwiLCBcImMtaXBcIiwgXCJzYy1zdGF0dXNcIiwgXCJjcy11cmktc3RlbVwiLCBcImNzLW1ldGhvZFwiLFxuICAgICAgICBcImNzLWhvc3RcIiwgXCJjcy11c2VyLWFnZW50XCIsIFwic2MtYnl0ZXNcIiwgXCJ0aW1lLXRha2VuXCIsIFwiYy1jb3VudHJ5XCIsXG4gICAgICBdLFxuICAgIH0pO1xuXG4gICAgLy8gQXR0YWNoIHJlYWwtdGltZSBsb2dzIHRvIHRoZSBkZWZhdWx0IGNhY2hlIGJlaGF2aW9yXG4gICAgY29uc3QgY2ZuRGlzdCA9IGRpc3RyaWJ1dGlvbi5ub2RlLmRlZmF1bHRDaGlsZCBhcyBjbG91ZGZyb250LkNmbkRpc3RyaWJ1dGlvbjtcbiAgICBjZm5EaXN0LmFkZFByb3BlcnR5T3ZlcnJpZGUoXG4gICAgICBcIkRpc3RyaWJ1dGlvbkNvbmZpZy5EZWZhdWx0Q2FjaGVCZWhhdmlvci5SZWFsdGltZUxvZ0NvbmZpZ0FyblwiLFxuICAgICAgcmVhbHRpbWVMb2dDb25maWcuYXR0ckFyblxuICAgICk7XG5cbiAgICAvLyAtLS0gRGFzaGJvYXJkOiBsaXN0IHJldm9rZWQgc2Vzc2lvbnMgZnJvbSBLVlMgLS0tXG4gICAgY29uc3QgbGlzdFJldm9rZWQgPSBuZXcgbGFtYmRhLkZ1bmN0aW9uKHRoaXMsIFwiTGlzdFJldm9rZWRcIiwge1xuICAgICAgcnVudGltZTogbGFtYmRhLlJ1bnRpbWUuTk9ERUpTXzIyX1gsXG4gICAgICBoYW5kbGVyOiBcImxpc3RfcmV2b2tlZC5oYW5kbGVyXCIsXG4gICAgICBjb2RlOiBsYW1iZGEuQ29kZS5mcm9tQXNzZXQoXCJsYW1iZGFcIiksXG4gICAgICB0aW1lb3V0OiBEdXJhdGlvbi5zZWNvbmRzKDEwKSxcbiAgICAgIGVudmlyb25tZW50OiB7IEtWU19BUk46IHRoaXMua3ZTdG9yZS5rZXlWYWx1ZVN0b3JlQXJuIH0sXG4gICAgfSk7XG4gICAgbGlzdFJldm9rZWQuYWRkVG9Sb2xlUG9saWN5KG5ldyBpYW0uUG9saWN5U3RhdGVtZW50KHtcbiAgICAgIGFjdGlvbnM6IFtcImNsb3VkZnJvbnQta2V5dmFsdWVzdG9yZTpMaXN0S2V5c1wiLCBcImNsb3VkZnJvbnQta2V5dmFsdWVzdG9yZTpEZXNjcmliZUtleVZhbHVlU3RvcmVcIl0sXG4gICAgICByZXNvdXJjZXM6IFt0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUFybl0sXG4gICAgfSkpO1xuXG4gICAgLy8gQWRkIC9yZXZva2VkIHRvIHRoZSBleGlzdGluZyBBUElcbiAgICBhcGkucm9vdC5hZGRSZXNvdXJjZShcInJldm9rZWRcIikuYWRkTWV0aG9kKFwiR0VUXCIsXG4gICAgICBuZXcgYXBpZ2F0ZXdheS5MYW1iZGFJbnRlZ3JhdGlvbihsaXN0UmV2b2tlZClcbiAgICApO1xuXG4gICAgLy8gRGVwbG95IGRhc2hib2FyZCBIVE1MIChhbG9uZ3NpZGUgZGVtbyBzaXRlIGlmIGVuYWJsZWQpXG4gICAgaWYgKGNvbmZpZy5tYWluLmVuYWJsZURlbW8pIHtcbiAgICAgIG5ldyBzM2RlcGxveS5CdWNrZXREZXBsb3ltZW50KHRoaXMsIFwiRGVwbG95RGFzaGJvYXJkXCIsIHtcbiAgICAgICAgc291cmNlczogW1xuICAgICAgICAgIHMzZGVwbG95LlNvdXJjZS5hc3NldChcInJlc291cmNlcy9kYXNoYm9hcmRcIiksXG4gICAgICAgICAgczNkZXBsb3kuU291cmNlLmRhdGEoXCJjb25maWcuanNcIixcbiAgICAgICAgICAgIGB3aW5kb3cuQ1RBX0NPTkZJRz17YXBpRW5kcG9pbnQ6XCIke2FwaS51cmwucmVwbGFjZSgvXFwvJC8sJycpfVwiLGNkbkRvbWFpbjpcImh0dHBzOi8vJHtkaXN0cmlidXRpb24uZGlzdHJpYnV0aW9uRG9tYWluTmFtZX1cIn07YFxuICAgICAgICAgICksXG4gICAgICAgIF0sXG4gICAgICAgIGRlc3RpbmF0aW9uQnVja2V0OiBkZW1vQnVja2V0ISxcbiAgICAgICAgZGVzdGluYXRpb25LZXlQcmVmaXg6IFwid2Vic2l0ZVwiLFxuICAgICAgICBwcnVuZTogZmFsc2UsXG4gICAgICB9KTtcbiAgICB9XG5cbiAgICAvLyAtLS0gS1ZTIENsZWFudXA6IHB1cmdlIGV4cGlyZWQgcmV2b2NhdGlvbnMgb24gYSBzY2hlZHVsZSAtLS1cbiAgICBjb25zdCBrdnNDbGVhbnVwID0gbmV3IGxhbWJkYS5GdW5jdGlvbih0aGlzLCBcIkt2c0NsZWFudXBcIiwge1xuICAgICAgcnVudGltZTogbGFtYmRhLlJ1bnRpbWUuTk9ERUpTXzIyX1gsXG4gICAgICBoYW5kbGVyOiBcImt2c19jbGVhbnVwLmhhbmRsZXJcIixcbiAgICAgIGNvZGU6IGxhbWJkYS5Db2RlLmZyb21Bc3NldChcImxhbWJkYVwiKSxcbiAgICAgIHRpbWVvdXQ6IER1cmF0aW9uLm1pbnV0ZXMoMiksXG4gICAgICBlbnZpcm9ubWVudDogeyBLVlNfQVJOOiB0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUFybiwgVFRMX0hPVVJTOiBcIjI0XCIgfSxcbiAgICB9KTtcbiAgICBrdnNDbGVhbnVwLmFkZFRvUm9sZVBvbGljeShuZXcgaWFtLlBvbGljeVN0YXRlbWVudCh7XG4gICAgICBhY3Rpb25zOiBbXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6TGlzdEtleXNcIiwgXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6RGVsZXRlS2V5XCIsIFwiY2xvdWRmcm9udC1rZXl2YWx1ZXN0b3JlOkRlc2NyaWJlS2V5VmFsdWVTdG9yZVwiXSxcbiAgICAgIHJlc291cmNlczogW3RoaXMua3ZTdG9yZS5rZXlWYWx1ZVN0b3JlQXJuXSxcbiAgICB9KSk7XG4gICAgbmV3IGV2ZW50cy5SdWxlKHRoaXMsIFwiS3ZzQ2xlYW51cFNjaGVkdWxlXCIsIHtcbiAgICAgIHNjaGVkdWxlOiBldmVudHMuU2NoZWR1bGUucmF0ZShEdXJhdGlvbi5ob3VycygxKSksXG4gICAgICB0YXJnZXRzOiBbbmV3IHRhcmdldHMuTGFtYmRhRnVuY3Rpb24oa3ZzQ2xlYW51cCldLFxuICAgIH0pO1xuXG4gICAgLy8gT3V0cHV0c1xuICAgIG5ldyBDZm5PdXRwdXQodGhpcywgXCJBUElFbmRwb2ludFwiLCB7IFxuICAgICAgdmFsdWU6IGBodHRwczovLyR7ZGlzdHJpYnV0aW9uLmRpc3RyaWJ1dGlvbkRvbWFpbk5hbWV9L2FwaWAsXG4gICAgICBkZXNjcmlwdGlvbjogXCJDVEEgQVBJIEVuZHBvaW50XCJcbiAgICB9KTtcbiAgICBcbiAgICBpZiAoY29uZmlnLm1haW4uZW5hYmxlRGVtbykge1xuICAgICAgbmV3IENmbk91dHB1dCh0aGlzLCBcIkRlbW9XZWJzaXRlVXJsXCIsIHsgXG4gICAgICAgIHZhbHVlOiBgaHR0cHM6Ly8ke2Rpc3RyaWJ1dGlvbi5kaXN0cmlidXRpb25Eb21haW5OYW1lfS93ZWJzaXRlL2luZGV4LXBhdGguaHRtbGAsXG4gICAgICAgIGRlc2NyaXB0aW9uOiBcIkNUQSBEZW1vIFdlYnNpdGUg4oCUIFBhdGggVG9rZW4gTW9kZVwiXG4gICAgICB9KTtcbiAgICAgIG5ldyBDZm5PdXRwdXQodGhpcywgXCJEZW1vV2Vic2l0ZUhlYWRlclVybFwiLCB7IFxuICAgICAgICB2YWx1ZTogYGh0dHBzOi8vJHtkaXN0cmlidXRpb24uZGlzdHJpYnV0aW9uRG9tYWluTmFtZX0vd2Vic2l0ZS9pbmRleC1oZWFkZXIuaHRtbGAsXG4gICAgICAgIGRlc2NyaXB0aW9uOiBcIkNUQSBEZW1vIFdlYnNpdGUg4oCUIEhlYWRlci1Pbmx5IFRva2VuIE1vZGVcIlxuICAgICAgfSk7XG4gICAgICBuZXcgQ2ZuT3V0cHV0KHRoaXMsIFwiRGVtb1dlYnNpdGVIeWJyaWRVcmxcIiwgeyBcbiAgICAgICAgdmFsdWU6IGBodHRwczovLyR7ZGlzdHJpYnV0aW9uLmRpc3RyaWJ1dGlvbkRvbWFpbk5hbWV9L3dlYnNpdGUvaW5kZXgtaHlicmlkLmh0bWxgLFxuICAgICAgICBkZXNjcmlwdGlvbjogXCJDVEEgRGVtbyBXZWJzaXRlIOKAlCBIeWJyaWQgKFBhdGggSW5pdCDihpIgSGVhZGVyIFJlbmV3YWwpXCJcbiAgICAgIH0pO1xuICAgIH1cbiAgICBcbiAgICBuZXcgQ2ZuT3V0cHV0KHRoaXMsIFwiS2V5VmFsdWVTdG9yZUlkXCIsIHsgXG4gICAgICB2YWx1ZTogdGhpcy5rdlN0b3JlLmtleVZhbHVlU3RvcmVJZCxcbiAgICAgIGRlc2NyaXB0aW9uOiBcIkNsb3VkRnJvbnQgS2V5VmFsdWVTdG9yZSBJRFwiXG4gICAgfSk7XG5cbiAgICBuZXcgQ2ZuT3V0cHV0KHRoaXMsIFwiU2VjcmV0QXJuXCIsIHtcbiAgICAgIHZhbHVlOiBzaWduaW5nU2VjcmV0LnNlY3JldEFybixcbiAgICAgIGRlc2NyaXB0aW9uOiBcIkNUQSBzaWduaW5nIHNlY3JldCBBUk5cIlxuICAgIH0pO1xuXG4gICAgbmV3IENmbk91dHB1dCh0aGlzLCBcIkNUQVN0YW5kYXJkXCIsIHtcbiAgICAgIHZhbHVlOiBcIkNUQS01MDA3LUJcIixcbiAgICAgIGRlc2NyaXB0aW9uOiBcIkltcGxlbWVudGVkIHN0YW5kYXJkIHZlcnNpb25cIlxuICAgIH0pO1xuXG4gICAgbmV3IENmbk91dHB1dCh0aGlzLCBcIlJvdGF0aW9uV29ya2Zsb3dcIiwge1xuICAgICAgdmFsdWU6IHJvdGF0aW9uV29ya2Zsb3cuc3RhdGVNYWNoaW5lTmFtZSxcbiAgICAgIGRlc2NyaXB0aW9uOiBcIktleSByb3RhdGlvbiBTdGVwIEZ1bmN0aW9ucyB3b3JrZmxvd1wiXG4gICAgfSk7XG5cbiAgICBuZXcgQ2ZuT3V0cHV0KHRoaXMsIFwiV2ViQWNsQXJuXCIsIHtcbiAgICAgIHZhbHVlOiB3ZWJBY2wuYXR0ckFybixcbiAgICAgIGRlc2NyaXB0aW9uOiBcIldBRnYyIFdlYiBBQ0wg4oCUIHJhdGUtbGltaXRzIFBPU1QgL2FwaS90b2tlblwiXG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIHBhcnNlUm90YXRpb25SYXRlKHJhdGU6IHN0cmluZyk6IER1cmF0aW9uIHtcbiAgICBjb25zdCBtYXRjaCA9IHJhdGUubWF0Y2goL14oXFxkKykoW21oZF0pJC8pO1xuICAgIGlmICghbWF0Y2gpIHJldHVybiBEdXJhdGlvbi5kYXlzKDMwKTtcbiAgICBjb25zdCB2YWx1ZSA9IHBhcnNlSW50KG1hdGNoWzFdKTtcbiAgICBzd2l0Y2ggKG1hdGNoWzJdKSB7XG4gICAgICBjYXNlICdtJzogcmV0dXJuIER1cmF0aW9uLm1pbnV0ZXModmFsdWUpO1xuICAgICAgY2FzZSAnaCc6IHJldHVybiBEdXJhdGlvbi5ob3Vycyh2YWx1ZSk7XG4gICAgICBjYXNlICdkJzogcmV0dXJuIER1cmF0aW9uLmRheXModmFsdWUpO1xuICAgICAgZGVmYXVsdDogcmV0dXJuIER1cmF0aW9uLmRheXMoMzApO1xuICAgIH1cbiAgfVxufVxuIl19