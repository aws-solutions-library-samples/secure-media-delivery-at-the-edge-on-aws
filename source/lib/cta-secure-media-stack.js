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
            runtime: aws_cdk_lib_1.aws_lambda.Runtime.RUBY_3_4,
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
            new aws_cdk_lib_1.CfnOutput(this, "DashboardUrl", {
                value: `https://${distribution.distributionDomainName}/website/dashboard.html`,
                description: "Revocation Dashboard with Bedrock Prompt Editor"
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY3RhLXNlY3VyZS1tZWRpYS1zdGFjay5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbImN0YS1zZWN1cmUtbWVkaWEtc3RhY2sudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsNkNBdUJxQjtBQUVyQiwrRUFBK0Y7QUFDL0YscUVBQStEO0FBTy9ELE1BQWEsbUJBQW9CLFNBQVEsbUJBQUs7SUFNNUMsWUFBWSxLQUFnQixFQUFFLEVBQVUsRUFBRSxRQUFrQyxFQUFFO1FBQzVFLEtBQUssQ0FBQyxLQUFLLEVBQUUsRUFBRSxFQUFFLEtBQUssQ0FBQyxDQUFDO1FBRXhCLE1BQU0sVUFBVSxHQUFHLElBQUksMEJBQVksQ0FBQyxJQUFJLEVBQUUsWUFBWSxFQUFFO1lBQ3RELElBQUksRUFBRSxRQUFRO1lBQ2QsT0FBTyxFQUFFLE1BQU07WUFDZixhQUFhLEVBQUUsQ0FBQyxNQUFNLEVBQUUsT0FBTyxDQUFDO1lBQ2hDLFdBQVcsRUFBRSxxQkFBcUI7U0FDbkMsQ0FBQyxDQUFDO1FBRUgsTUFBTSxZQUFZLEdBQUcsSUFBSSwwQkFBWSxDQUFDLElBQUksRUFBRSxjQUFjLEVBQUU7WUFDMUQsSUFBSSxFQUFFLFFBQVE7WUFDZCxPQUFPLEVBQUUsdUJBQXVCO1lBQ2hDLGFBQWEsRUFBRSxDQUFDLHNCQUFzQixFQUFFLHVCQUF1QixDQUFDO1lBQ2hFLFdBQVcsRUFBRSwrQkFBK0I7U0FDN0MsQ0FBQyxDQUFDO1FBRUgsTUFBTSxNQUFNLEdBQUcsS0FBSyxDQUFDLE1BQU0sSUFBSTtZQUM3QixJQUFJLEVBQUU7Z0JBQ0osVUFBVSxFQUFFLFVBQVUsQ0FBQyxhQUFhLEtBQUssTUFBTTthQUNoRDtZQUNELE9BQU8sRUFBRTtnQkFDUCxLQUFLLEVBQUUsWUFBWSxDQUFDLGFBQWE7YUFDbEM7U0FDRixDQUFDO1FBRUYsa0JBQWtCO1FBQ2xCLE1BQU0sYUFBYSxHQUFHLElBQUksZ0NBQWMsQ0FBQyxNQUFNLENBQUMsSUFBSSxFQUFFLFFBQVEsRUFBRTtZQUM5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QUFDLGdCQUFnQjtZQUN4QyxXQUFXLEVBQUUsc0NBQXNDO1NBQ3BELENBQUMsQ0FBQztRQUVILElBQUksdUJBQVMsQ0FBQyxJQUFJLEVBQUUsV0FBVyxFQUFFO1lBQy9CLEtBQUssRUFBRSxNQUFNLENBQUMsT0FBTztZQUNyQixXQUFXLEVBQUUsNkNBQTZDO1NBQzNELENBQUMsQ0FBQztJQUNMLENBQUM7SUFFTyxpQkFBaUIsQ0FBQyxJQUFZO1FBQ3BDLE1BQU0sS0FBSyxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsZ0JBQWdCLENBQUMsQ0FBQztRQUMzQyxJQUFJLENBQUMsS0FBSztZQUFFLE9BQU8sc0JBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFDLENBQUM7UUFDckMsTUFBTSxLQUFLLEdBQUcsUUFBUSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO1FBQ2pDLFFBQVEsS0FBSyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUM7WUFDakIsS0FBSyxHQUFHLENBQUMsQ0FBQyxPQUFPLHNCQUFRLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFDO1lBQ3pDLEtBQUssR0FBRyxDQUFDLENBQUMsT0FBTyxzQkFBUSxDQUFDLEtBQUssQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUN2QyxLQUFLLEdBQUcsQ0FBQyxDQUFDLE9BQU8sc0JBQVEsQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUM7WUFDdEMsT0FBTyxDQUFDLENBQUMsT0FBTyxzQkFBUSxDQUFDLElBQUksQ0FBQyxFQUFFLENBQUMsQ0FBQztRQUNwQyxDQUFDO0lBQ0gsQ0FBQztDQUNGO0FBaGZELGtEQWdmQyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7XG4gIFN0YWNrLFxuICBTdGFja1Byb3BzLFxuICBBd3MsXG4gIFJlbW92YWxQb2xpY3ksXG4gIER1cmF0aW9uLFxuICBDZm5PdXRwdXQsXG4gIENmblBhcmFtZXRlcixcbiAgQ3VzdG9tUmVzb3VyY2UsXG4gIGF3c19jbG91ZGZyb250IGFzIGNsb3VkZnJvbnQsXG4gIGF3c19sYW1iZGEgYXMgbGFtYmRhLFxuICBhd3NfYXBpZ2F0ZXdheSBhcyBhcGlnYXRld2F5LFxuICBhd3Nfc2VjcmV0c21hbmFnZXIgYXMgc2VjcmV0c21hbmFnZXIsXG4gIGF3c19zMyBhcyBzMyxcbiAgYXdzX3MzX2RlcGxveW1lbnQgYXMgczNkZXBsb3ksXG4gIGF3c19pYW0gYXMgaWFtLFxuICBhd3Nfc3RlcGZ1bmN0aW9ucyBhcyBzZm4sXG4gIGF3c19zdGVwZnVuY3Rpb25zX3Rhc2tzIGFzIHRhc2tzLFxuICBhd3NfZXZlbnRzIGFzIGV2ZW50cyxcbiAgYXdzX2V2ZW50c190YXJnZXRzIGFzIHRhcmdldHMsXG4gIGF3c19raW5lc2lzIGFzIGtpbmVzaXMsXG4gIGF3c193YWZ2MiBhcyB3YWZ2MixcbiAgY3VzdG9tX3Jlc291cmNlcyxcbn0gZnJvbSBcImF3cy1jZGstbGliXCI7XG5cbmltcG9ydCB7IEh0dHBPcmlnaW4sIFJlc3RBcGlPcmlnaW4sIFMzQnVja2V0T3JpZ2luIH0gZnJvbSBcImF3cy1jZGstbGliL2F3cy1jbG91ZGZyb250LW9yaWdpbnNcIjtcbmltcG9ydCB7IE5vZGVqc0Z1bmN0aW9uIH0gZnJvbSBcImF3cy1jZGstbGliL2F3cy1sYW1iZGEtbm9kZWpzXCI7XG5pbXBvcnQgeyBDb25zdHJ1Y3QgfSBmcm9tIFwiY29uc3RydWN0c1wiO1xuXG5leHBvcnQgaW50ZXJmYWNlIENUQVNlY3VyZU1lZGlhU3RhY2tQcm9wcyBleHRlbmRzIFN0YWNrUHJvcHMge1xuICByZWFkb25seSBjb25maWc/OiBhbnk7XG59XG5cbmV4cG9ydCBjbGFzcyBDVEFTZWN1cmVNZWRpYVN0YWNrIGV4dGVuZHMgU3RhY2sge1xuICBwdWJsaWMgcmVhZG9ubHkga3ZTdG9yZTogY2xvdWRmcm9udC5LZXlWYWx1ZVN0b3JlO1xuICBwdWJsaWMgcmVhZG9ubHkgZGlzdHJpYnV0aW9uOiBjbG91ZGZyb250LkRpc3RyaWJ1dGlvbjtcbiAgcHVibGljIHJlYWRvbmx5IGRlbW9CdWNrZXQ6IHMzLkJ1Y2tldDtcbiAgcHVibGljIHJlYWRvbmx5IGxvZ1N0cmVhbToga2luZXNpcy5TdHJlYW07XG4gIFxuICBjb25zdHJ1Y3RvcihzY29wZTogQ29uc3RydWN0LCBpZDogc3RyaW5nLCBwcm9wczogQ1RBU2VjdXJlTWVkaWFTdGFja1Byb3BzID0ge30pIHtcbiAgICBzdXBlcihzY29wZSwgaWQsIHByb3BzKTtcblxuICAgIGNvbnN0IGVuYWJsZURlbW8gPSBuZXcgQ2ZuUGFyYW1ldGVyKHRoaXMsIFwiRW5hYmxlRGVtb1wiLCB7XG4gICAgICB0eXBlOiBcIlN0cmluZ1wiLFxuICAgICAgZGVmYXVsdDogXCJ0cnVlXCIsXG4gICAgICBhbGxvd2VkVmFsdWVzOiBbXCJ0cnVlXCIsIFwiZmFsc2VcIl0sXG4gICAgICBkZXNjcmlwdGlvbjogXCJEZXBsb3kgZGVtbyB3ZWJzaXRlXCIsXG4gICAgfSk7XG5cbiAgICBjb25zdCBiZWRyb2NrTW9kZWwgPSBuZXcgQ2ZuUGFyYW1ldGVyKHRoaXMsIFwiQmVkcm9ja01vZGVsXCIsIHtcbiAgICAgIHR5cGU6IFwiU3RyaW5nXCIsXG4gICAgICBkZWZhdWx0OiBcImFtYXpvbi5ub3ZhLWxpdGUtdjE6MFwiLFxuICAgICAgYWxsb3dlZFZhbHVlczogW1wiYW1hem9uLm5vdmEtcHJvLXYxOjBcIiwgXCJhbWF6b24ubm92YS1saXRlLXYxOjBcIl0sXG4gICAgICBkZXNjcmlwdGlvbjogXCJCZWRyb2NrIG1vZGVsIGZvciBBSSBhbmFseXNpc1wiLFxuICAgIH0pO1xuXG4gICAgY29uc3QgY29uZmlnID0gcHJvcHMuY29uZmlnIHx8IHtcbiAgICAgIG1haW46IHtcbiAgICAgICAgZW5hYmxlRGVtbzogZW5hYmxlRGVtby52YWx1ZUFzU3RyaW5nID09PSBcInRydWVcIixcbiAgICAgIH0sXG4gICAgICBiZWRyb2NrOiB7XG4gICAgICAgIG1vZGVsOiBiZWRyb2NrTW9kZWwudmFsdWVBc1N0cmluZyxcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgLy8gQ1RBIHNpZ25pbmcga2V5XG4gICAgY29uc3Qgc2lnbmluZ1NlY3JldCA9IG5ldyBzZWNyZXRzbWFuYWdlci5TZWNyZXQodGhpcywgXCJDVEFLZXlcIiwge1xuICAgICAgZ2VuZXJhdGVTZWNyZXRTdHJpbmc6IHtcbiAgICAgICAgc2VjcmV0U3RyaW5nVGVtcGxhdGU6ICd7XCJhbGdvcml0aG1cIjpcIkhNQUMtU0hBMjU2XCJ9JyxcbiAgICAgICAgZ2VuZXJhdGVTdHJpbmdLZXk6IFwic2lnbmluZ0tleVwiLFxuICAgICAgICBwYXNzd29yZExlbmd0aDogNjQsXG4gICAgICB9LFxuICAgICAgcmVtb3ZhbFBvbGljeTogUmVtb3ZhbFBvbGljeS5ERVNUUk9ZLFxuICAgIH0pO1xuXG4gICAgLy8gQ2xvdWRGcm9udCBLZXlWYWx1ZVN0b3JlIGZvciByZXZvY2F0aW9uXG4gICAgdGhpcy5rdlN0b3JlID0gbmV3IGNsb3VkZnJvbnQuS2V5VmFsdWVTdG9yZSh0aGlzLCBcIkNUQVJldm9jYXRpb25TdG9yZVwiLCB7XG4gICAgICBjb21tZW50OiBcIkNUQSB0b2tlbiByZXZvY2F0aW9uIGxpc3RcIixcbiAgICB9KTtcblxuICAgIC8vIENUQSB2YWxpZGF0b3IgZnVuY3Rpb24uXG4gICAgLy9cbiAgICAvLyBFeHBsaWNpdCBhZGREZXBlbmRlbmN5IG9uIHRoZSBLVlM6IENsb3VkRnJvbnQgS2V5VmFsdWVTdG9yZSBpcyBhXG4gICAgLy8gdHdvLXBoYXNlIEFXUyByZXNvdXJjZSAoUHJvdmlzaW9uaW5nIC0+IFJlYWR5KS4gVGhlIEwyIGNvbnN0cnVjdFxuICAgIC8vIHJldHVybnMgdGhlIEFSTiBiZWZvcmUgdGhlIHN0b3JlIGlzIFJlYWR5LCBzbyB3aXRob3V0IHRoaXNcbiAgICAvLyBkZXBlbmRlbmN5IENESyBjYW4gb3JkZXIgdGhlIENGIEZ1bmN0aW9uJ3MgS2V5VmFsdWVTdG9yZUFzc29jaWF0aW9uc1xuICAgIC8vIGJlZm9yZSB0aGUgS1ZTIGlzIFJlYWR5IGFuZCBDbG91ZEZvcm1hdGlvbiBmYWlscyB3aXRoOlxuICAgIC8vICAgXCJjYW5ub3QgYmUgYXNzb2NpYXRlZCBiZWZvcmUgdGhlIHJlc291cmNlIGlzIHByb3Zpc2lvbmVkXCJcbiAgICAvLyBUaGUgZmFpbHVyZSBpcyBpbnRlcm1pdHRlbnQg4oCUIGl0IGRlcGVuZHMgb24gQ0RLJ3MgZ3JhcGggdHJhdmVyc2FsXG4gICAgLy8gb3JkZXIg4oCUIHdoaWNoIG1ha2VzIGl0IGVzcGVjaWFsbHkgZnJ1c3RyYXRpbmcgdG8gZGVidWcgb24gYSBmcmVzaFxuICAgIC8vIGRlcGxveS5cbiAgICBjb25zdCB2YWxpZGF0b3IgPSBuZXcgY2xvdWRmcm9udC5GdW5jdGlvbih0aGlzLCBcIkNUQVZhbGlkYXRvclwiLCB7XG4gICAgICBjb2RlOiBjbG91ZGZyb250LkZ1bmN0aW9uQ29kZS5mcm9tRmlsZSh7IGZpbGVQYXRoOiBcImxhbWJkYS9jdGFfdG9rZW5fdmFsaWRhdG9yLmpzXCIgfSksXG4gICAgICBmdW5jdGlvbk5hbWU6IGAke0F3cy5TVEFDS19OQU1FfS1DVEEtVmFsaWRhdG9yYCxcbiAgICAgIHJ1bnRpbWU6IGNsb3VkZnJvbnQuRnVuY3Rpb25SdW50aW1lLkpTXzJfMCxcbiAgICAgIGtleVZhbHVlU3RvcmU6IHRoaXMua3ZTdG9yZSxcbiAgICB9KTtcbiAgICB2YWxpZGF0b3Iubm9kZS5hZGREZXBlbmRlbmN5KHRoaXMua3ZTdG9yZSk7XG5cbiAgICAvLyBUb2tlbiBnZW5lcmF0b3IgKE5vZGUgU0RLKVxuICAgIC8vIE5vZGVqc0Z1bmN0aW9uIChlc2J1aWxkKSBidW5kbGVzIHRoZSBoYW5kbGVyIHRvZ2V0aGVyIHdpdGggaXRzXG4gICAgLy8gdGhpcmQtcGFydHkgZGVwZW5kZW5jeSBjYm9yLXgsIHdoaWNoIGlzIE5PVCBwcm92aWRlZCBieSB0aGUgTGFtYmRhXG4gICAgLy8gTm9kZS5qcyBydW50aW1lLiBBIHBsYWluIENvZGUuZnJvbUFzc2V0KFwibGFtYmRhXCIpIHNoaXBzIG5vIG5vZGVfbW9kdWxlcyxcbiAgICAvLyBzbyByZXF1aXJlKCdjYm9yLXgnKSBmYWlscyBhdCBtb2R1bGUgaW5pdCBhbmQgQVBJIEdhdGV3YXkgcmV0dXJucyBhIDUwMlxuICAgIC8vIHdpdGggbm8gQ09SUyBoZWFkZXJzIOKAlCBzdXJmYWNpbmcgaW4gdGhlIGJyb3dzZXIgYXMgYSBDT1JTIGVycm9yLlxuICAgIC8vIFRoZSBBV1MgU0RLIHYzIHBhY2thZ2VzIChAYXdzLXNkay8qKSByZW1haW4gZXh0ZXJuYWxpemVkIGJ5IGRlZmF1bHRcbiAgICAvLyBzaW5jZSB0aGV5IEFSRSBwcmVzZW50IGluIHRoZSBydW50aW1lLlxuICAgIGNvbnN0IGdlbmVyYXRvciA9IG5ldyBOb2RlanNGdW5jdGlvbih0aGlzLCBcIkNUQUdlbmVyYXRvclwiLCB7XG4gICAgICBydW50aW1lOiBsYW1iZGEuUnVudGltZS5OT0RFSlNfMjJfWCxcbiAgICAgIGVudHJ5OiBcImxhbWJkYS9jdGFfdG9rZW5fZ2VuZXJhdG9yLmpzXCIsXG4gICAgICBoYW5kbGVyOiBcImhhbmRsZXJcIixcbiAgICAgIHRpbWVvdXQ6IER1cmF0aW9uLnNlY29uZHMoMTApLFxuICAgICAgZW52aXJvbm1lbnQ6IHsgU0VDUkVUX05BTUU6IHNpZ25pbmdTZWNyZXQuc2VjcmV0TmFtZSB9LFxuICAgIH0pO1xuXG4gICAgLy8gVG9rZW4gZ2VuZXJhdG9yIChQeXRob24gU0RLKVxuICAgIGNvbnN0IGdlbmVyYXRvclB5dGhvbiA9IG5ldyBsYW1iZGEuRnVuY3Rpb24odGhpcywgXCJDVEFHZW5lcmF0b3JQeXRob25cIiwge1xuICAgICAgcnVudGltZTogbGFtYmRhLlJ1bnRpbWUuUFlUSE9OXzNfMTMsXG4gICAgICBoYW5kbGVyOiBcImhhbmRsZXIuaGFuZGxlclwiLFxuICAgICAgY29kZTogbGFtYmRhLkNvZGUuZnJvbUFzc2V0KFwibGFtYmRhLXB5dGhvblwiKSxcbiAgICAgIHRpbWVvdXQ6IER1cmF0aW9uLnNlY29uZHMoMTApLFxuICAgICAgZW52aXJvbm1lbnQ6IHsgU0VDUkVUX05BTUU6IHNpZ25pbmdTZWNyZXQuc2VjcmV0TmFtZSB9LFxuICAgIH0pO1xuXG4gICAgLy8gVG9rZW4gZ2VuZXJhdG9yIChSdWJ5IFNESylcbiAgICBjb25zdCBnZW5lcmF0b3JSdWJ5ID0gbmV3IGxhbWJkYS5GdW5jdGlvbih0aGlzLCBcIkNUQUdlbmVyYXRvclJ1YnlcIiwge1xuICAgICAgcnVudGltZTogbGFtYmRhLlJ1bnRpbWUuUlVCWV8zXzQsXG4gICAgICBoYW5kbGVyOiBcImhhbmRsZXIuaGFuZGxlclwiLFxuICAgICAgY29kZTogbGFtYmRhLkNvZGUuZnJvbUFzc2V0KFwibGFtYmRhLXJ1YnlcIiksXG4gICAgICB0aW1lb3V0OiBEdXJhdGlvbi5zZWNvbmRzKDEwKSxcbiAgICAgIGVudmlyb25tZW50OiB7IFNFQ1JFVF9OQU1FOiBzaWduaW5nU2VjcmV0LnNlY3JldE5hbWUgfSxcbiAgICB9KTtcblxuICAgIC8vIFRva2VuIHJldm9jYXRpb24gaGFuZGxlclxuICAgIGNvbnN0IHJldm9rZXIgPSBuZXcgbGFtYmRhLkZ1bmN0aW9uKHRoaXMsIFwiQ1RBUmV2b2tlclwiLCB7XG4gICAgICBydW50aW1lOiBsYW1iZGEuUnVudGltZS5OT0RFSlNfMjJfWCxcbiAgICAgIGhhbmRsZXI6IFwiY3RhX3Jldm9jYXRpb24uaGFuZGxlclwiLFxuICAgICAgY29kZTogbGFtYmRhLkNvZGUuZnJvbUFzc2V0KFwibGFtYmRhXCIpLFxuICAgICAgdGltZW91dDogRHVyYXRpb24uc2Vjb25kcygxMCksXG4gICAgICBlbnZpcm9ubWVudDogeyBLVlNfQVJOOiB0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUFybiB9LFxuICAgIH0pO1xuXG4gICAgc2lnbmluZ1NlY3JldC5ncmFudFJlYWQoZ2VuZXJhdG9yKTtcbiAgICBzaWduaW5nU2VjcmV0LmdyYW50UmVhZChnZW5lcmF0b3JQeXRob24pO1xuICAgIHNpZ25pbmdTZWNyZXQuZ3JhbnRSZWFkKGdlbmVyYXRvclJ1YnkpO1xuXG4gICAgLy8gR3JhbnQgS1ZTIHVwZGF0ZSBwZXJtaXNzaW9uIHZpYSBJQU0gcG9saWN5XG4gICAgcmV2b2tlci5hZGRUb1JvbGVQb2xpY3kobmV3IGlhbS5Qb2xpY3lTdGF0ZW1lbnQoe1xuICAgICAgZWZmZWN0OiBpYW0uRWZmZWN0LkFMTE9XLFxuICAgICAgYWN0aW9uczogW1wiY2xvdWRmcm9udC1rZXl2YWx1ZXN0b3JlOlB1dEtleVwiLCBcImNsb3VkZnJvbnQta2V5dmFsdWVzdG9yZTpEZXNjcmliZUtleVZhbHVlU3RvcmVcIl0sXG4gICAgICByZXNvdXJjZXM6IFt0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUFybl0sXG4gICAgfSkpO1xuXG4gICAgLy8gLS0tIEtleSBzeW5jIExhbWJkYSAoY3VzdG9tIHJlc291cmNlICsgcm90YXRpb24pIC0tLVxuICAgIGNvbnN0IHN5bmNLZXlzVG9LdnMgPSBuZXcgbGFtYmRhLkZ1bmN0aW9uKHRoaXMsIFwiU3luY0tleXNUb0t2c1wiLCB7XG4gICAgICBydW50aW1lOiBsYW1iZGEuUnVudGltZS5OT0RFSlNfMjJfWCxcbiAgICAgIGhhbmRsZXI6IFwiaW5kZXguaGFuZGxlclwiLFxuICAgICAgY29kZTogbGFtYmRhLkNvZGUuZnJvbUFzc2V0KFwibGFtYmRhL3N5bmNfa2V5c1wiKSxcbiAgICAgIHRpbWVvdXQ6IER1cmF0aW9uLnNlY29uZHMoMzApLFxuICAgICAgZW52aXJvbm1lbnQ6IHtcbiAgICAgICAgU0VDUkVUX05BTUU6IHNpZ25pbmdTZWNyZXQuc2VjcmV0TmFtZSxcbiAgICAgICAgS1ZTX0FSTjogdGhpcy5rdlN0b3JlLmtleVZhbHVlU3RvcmVBcm4sXG4gICAgICB9LFxuICAgIH0pO1xuXG4gICAgc2lnbmluZ1NlY3JldC5ncmFudFJlYWQoc3luY0tleXNUb0t2cyk7XG4gICAgc2lnbmluZ1NlY3JldC5ncmFudFdyaXRlKHN5bmNLZXlzVG9LdnMpO1xuICAgIHN5bmNLZXlzVG9LdnMuYWRkVG9Sb2xlUG9saWN5KG5ldyBpYW0uUG9saWN5U3RhdGVtZW50KHtcbiAgICAgIGVmZmVjdDogaWFtLkVmZmVjdC5BTExPVyxcbiAgICAgIGFjdGlvbnM6IFtcbiAgICAgICAgXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6UHV0S2V5XCIsXG4gICAgICAgIFwiY2xvdWRmcm9udC1rZXl2YWx1ZXN0b3JlOkRlc2NyaWJlS2V5VmFsdWVTdG9yZVwiLFxuICAgICAgXSxcbiAgICAgIHJlc291cmNlczogW3RoaXMua3ZTdG9yZS5rZXlWYWx1ZVN0b3JlQXJuXSxcbiAgICB9KSk7XG5cbiAgICAvLyBDdXN0b20gcmVzb3VyY2U6IHN5bmMga2V5IHRvIEtWUyBvbiBkZXBsb3lcbiAgICBjb25zdCBrZXlTeW5jUHJvdmlkZXIgPSBuZXcgY3VzdG9tX3Jlc291cmNlcy5Qcm92aWRlcih0aGlzLCBcIktleVN5bmNQcm92aWRlclwiLCB7XG4gICAgICBvbkV2ZW50SGFuZGxlcjogc3luY0tleXNUb0t2cyxcbiAgICB9KTtcblxuICAgIG5ldyBDdXN0b21SZXNvdXJjZSh0aGlzLCBcIktleVN5bmNSZXNvdXJjZVwiLCB7XG4gICAgICBzZXJ2aWNlVG9rZW46IGtleVN5bmNQcm92aWRlci5zZXJ2aWNlVG9rZW4sXG4gICAgICBwcm9wZXJ0aWVzOiB7XG4gICAgICAgIC8vIEZvcmNlIHVwZGF0ZSBvbiBlYWNoIGRlcGxveSB0byBlbnN1cmUga2V5IGlzIHN5bmNlZFxuICAgICAgICBUaW1lc3RhbXA6IERhdGUubm93KCkudG9TdHJpbmcoKSxcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICAvLyAtLS0gS2V5IHJvdGF0aW9uIHdvcmtmbG93IC0tLVxuICAgIGNvbnN0IHJvdGF0ZUtleVRhc2sgPSBuZXcgdGFza3MuTGFtYmRhSW52b2tlKHRoaXMsIFwiUm90YXRlU2lnbmluZ0tleVwiLCB7XG4gICAgICBsYW1iZGFGdW5jdGlvbjogc3luY0tleXNUb0t2cyxcbiAgICAgIHBheWxvYWQ6IHNmbi5UYXNrSW5wdXQuZnJvbU9iamVjdCh7IHJvdGF0ZTogdHJ1ZSB9KSxcbiAgICAgIHJlc3VsdFBhdGg6IHNmbi5Kc29uUGF0aC5ESVNDQVJELFxuICAgIH0pO1xuXG4gICAgY29uc3Qgcm90YXRpb25Xb3JrZmxvdyA9IG5ldyBzZm4uU3RhdGVNYWNoaW5lKHRoaXMsIFwiS2V5Um90YXRpb25Xb3JrZmxvd1wiLCB7XG4gICAgICBzdGF0ZU1hY2hpbmVOYW1lOiBgJHtBd3MuU1RBQ0tfTkFNRX1fUm90YXRlS2V5c2AsXG4gICAgICBkZWZpbml0aW9uQm9keTogc2ZuLkRlZmluaXRpb25Cb2R5LmZyb21DaGFpbmFibGUocm90YXRlS2V5VGFzayksXG4gICAgICB0aW1lb3V0OiBEdXJhdGlvbi5taW51dGVzKDUpLFxuICAgIH0pO1xuXG4gICAgLy8gUm90YXRlIGtleXMgbW9udGhseSBieSBkZWZhdWx0XG4gICAgY29uc3Qgcm90YXRpb25TY2hlZHVsZSA9IGNvbmZpZy5tYWluLnJvdGF0aW9uRnJlcXVlbmN5IHx8IFwiMzBkXCI7XG4gICAgY29uc3Qgcm90YXRpb25SYXRlID0gdGhpcy5wYXJzZVJvdGF0aW9uUmF0ZShyb3RhdGlvblNjaGVkdWxlKTtcbiAgICBuZXcgZXZlbnRzLlJ1bGUodGhpcywgXCJLZXlSb3RhdGlvblNjaGVkdWxlXCIsIHtcbiAgICAgIHNjaGVkdWxlOiBldmVudHMuU2NoZWR1bGUucmF0ZShyb3RhdGlvblJhdGUpLFxuICAgICAgdGFyZ2V0czogW25ldyB0YXJnZXRzLlNmblN0YXRlTWFjaGluZShyb3RhdGlvbldvcmtmbG93KV0sXG4gICAgfSk7XG5cbiAgICAvLyBBUEkgR2F0ZXdheVxuICAgIGNvbnN0IGFwaSA9IG5ldyBhcGlnYXRld2F5LlJlc3RBcGkodGhpcywgXCJDVEFBUElcIiwge1xuICAgICAgcmVzdEFwaU5hbWU6IFwiQ1RBIFRva2VuIEFQSVwiLFxuICAgICAgZGVmYXVsdENvcnNQcmVmbGlnaHRPcHRpb25zOiB7XG4gICAgICAgIGFsbG93T3JpZ2luczogYXBpZ2F0ZXdheS5Db3JzLkFMTF9PUklHSU5TLFxuICAgICAgICBhbGxvd01ldGhvZHM6IGFwaWdhdGV3YXkuQ29ycy5BTExfTUVUSE9EUyxcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICAvLyBBdHRhY2ggQ09SUyBoZWFkZXJzIHRvIEFQSSBHYXRld2F5J3MgZGVmYXVsdCBnYXRld2F5IHJlc3BvbnNlcyBzbyB0aGF0XG4gICAgLy8gaW50ZWdyYXRpb24gZXJyb3JzIChlLmcuIGEgTGFtYmRhIDV4eC90aW1lb3V0LCBvciBhIDR4eCkgc3RpbGwgY2FycnlcbiAgICAvLyBBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4uIFdpdGhvdXQgdGhpcywgYW4gZXJyb3JlZCByZXF1ZXN0IHJldHVybnMgYVxuICAgIC8vIHJlc3BvbnNlIHdpdGggbm8gQ09SUyBoZWFkZXIsIHdoaWNoIGJyb3dzZXJzIHN1cmZhY2UgYXMgYSBtaXNsZWFkaW5nXG4gICAgLy8gXCJibG9ja2VkIGJ5IENPUlMgcG9saWN5XCIgZXJyb3IgdGhhdCBtYXNrcyB0aGUgcmVhbCBzdGF0dXMgY29kZS5cbiAgICBjb25zdCBjb3JzUmVzcG9uc2VIZWFkZXJzID0ge1xuICAgICAgXCJBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW5cIjogXCInKidcIixcbiAgICAgIFwiQWNjZXNzLUNvbnRyb2wtQWxsb3ctSGVhZGVyc1wiOiBcIicqJ1wiLFxuICAgIH07XG4gICAgYXBpLmFkZEdhdGV3YXlSZXNwb25zZShcIkRlZmF1bHQ0WFhcIiwge1xuICAgICAgdHlwZTogYXBpZ2F0ZXdheS5SZXNwb25zZVR5cGUuREVGQVVMVF80WFgsXG4gICAgICByZXNwb25zZUhlYWRlcnM6IGNvcnNSZXNwb25zZUhlYWRlcnMsXG4gICAgfSk7XG4gICAgYXBpLmFkZEdhdGV3YXlSZXNwb25zZShcIkRlZmF1bHQ1WFhcIiwge1xuICAgICAgdHlwZTogYXBpZ2F0ZXdheS5SZXNwb25zZVR5cGUuREVGQVVMVF81WFgsXG4gICAgICByZXNwb25zZUhlYWRlcnM6IGNvcnNSZXNwb25zZUhlYWRlcnMsXG4gICAgfSk7XG5cbiAgICBjb25zdCB0b2tlblJlc291cmNlID0gYXBpLnJvb3QuYWRkUmVzb3VyY2UoXCJ0b2tlblwiKTtcbiAgICB0b2tlblJlc291cmNlLmFkZE1ldGhvZChcIlBPU1RcIiwgbmV3IGFwaWdhdGV3YXkuTGFtYmRhSW50ZWdyYXRpb24oZ2VuZXJhdG9yKSk7XG5cbiAgICBjb25zdCB0b2tlblB5dGhvblJlc291cmNlID0gYXBpLnJvb3QuYWRkUmVzb3VyY2UoXCJ0b2tlbi1weXRob25cIik7XG4gICAgdG9rZW5QeXRob25SZXNvdXJjZS5hZGRNZXRob2QoXCJQT1NUXCIsIG5ldyBhcGlnYXRld2F5LkxhbWJkYUludGVncmF0aW9uKGdlbmVyYXRvclB5dGhvbikpO1xuXG4gICAgY29uc3QgdG9rZW5SdWJ5UmVzb3VyY2UgPSBhcGkucm9vdC5hZGRSZXNvdXJjZShcInRva2VuLXJ1YnlcIik7XG4gICAgdG9rZW5SdWJ5UmVzb3VyY2UuYWRkTWV0aG9kKFwiUE9TVFwiLCBuZXcgYXBpZ2F0ZXdheS5MYW1iZGFJbnRlZ3JhdGlvbihnZW5lcmF0b3JSdWJ5KSk7XG4gICAgXG4gICAgY29uc3QgcmV2b2tlUmVzb3VyY2UgPSBhcGkucm9vdC5hZGRSZXNvdXJjZShcInJldm9rZVwiKTtcbiAgICByZXZva2VSZXNvdXJjZS5hZGRNZXRob2QoXCJQT1NUXCIsIG5ldyBhcGlnYXRld2F5LkxhbWJkYUludGVncmF0aW9uKHJldm9rZXIpKTtcblxuICAgIC8vIFdBRnYyIFdlYiBBQ0wg4oCUIHJhdGUtbGltaXQgUE9TVCAvYXBpL3Rva2VuIHBlciBzb3VyY2UgSVAuXG4gICAgLy86IGF1dG9tYXRlZC1zY3JhcGluZyBtaXRpZ2F0aW9uLiBSYXRlLWJhc2VkIHJ1bGVzIHVzZSBhXG4gICAgLy8gcm9sbGluZyA1LW1pbnV0ZSB3aW5kb3c7IDMwMCByZXEvNW1pbiDiiYggNjAgcmVxL21pbiBwZXIgSVAsIHdlbGxcbiAgICAvLyBhYm92ZSBsZWdpdGltYXRlIHBsYXllciB0cmFmZmljIChtaW50IG9uY2Ug4oaSIDJoIFRUTCDihpIgbmV4dCBtaW50KVxuICAgIC8vIGJ1dCB0aWdodCBlbm91Z2ggdG8gc3RvcCBhIG1pbnQteW91ci1vd24tdG9rZW4gc2NyYXBlci5cbiAgICAvLyBCbG9ja2VkIHJlcXVlc3RzIGdldCBhIGN1c3RvbSA0MjkgcmVzcG9uc2UgaW5zdGVhZCBvZiB0aGUgZGVmYXVsdCA0MDMuXG4gICAgY29uc3QgcmF0ZUxpbWl0Qm9keSA9IFwiQ1RBV2ViQWNsUmF0ZUxpbWl0NDI5XCI7XG4gICAgY29uc3Qgd2ViQWNsID0gbmV3IHdhZnYyLkNmbldlYkFDTCh0aGlzLCBcIkNUQVdlYkFjbFwiLCB7XG4gICAgICBuYW1lOiBgJHtBd3MuU1RBQ0tfTkFNRX0tdG9rZW4tcmF0ZS1saW1pdGAsXG4gICAgICBkZXNjcmlwdGlvbjogXCJSYXRlLWxpbWl0IFBPU1QgL2FwaS90b2tlbiB0byBtaXRpZ2F0ZSBhdXRvbWF0ZWQgQ1dUIG1pbnRpbmdcIixcbiAgICAgIHNjb3BlOiBcIkNMT1VERlJPTlRcIixcbiAgICAgIGRlZmF1bHRBY3Rpb246IHsgYWxsb3c6IHt9IH0sXG4gICAgICB2aXNpYmlsaXR5Q29uZmlnOiB7XG4gICAgICAgIGNsb3VkV2F0Y2hNZXRyaWNzRW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgbWV0cmljTmFtZTogYCR7QXdzLlNUQUNLX05BTUV9LXdlYi1hY2xgLFxuICAgICAgICBzYW1wbGVkUmVxdWVzdHNFbmFibGVkOiB0cnVlLFxuICAgICAgfSxcbiAgICAgIGN1c3RvbVJlc3BvbnNlQm9kaWVzOiB7XG4gICAgICAgIFtyYXRlTGltaXRCb2R5XToge1xuICAgICAgICAgIGNvbnRlbnRUeXBlOiBcIkFQUExJQ0FUSU9OX0pTT05cIixcbiAgICAgICAgICBjb250ZW50OiBKU09OLnN0cmluZ2lmeSh7IGVycm9yOiBcInJhdGVfbGltaXRlZFwiLCBtZXNzYWdlOiBcIlRvbyBtYW55IHRva2VuIG1pbnQgcmVxdWVzdHMgZnJvbSB0aGlzIElQOyB0cnkgYWdhaW4gaW4gYSBmZXcgbWludXRlcy5cIiB9KSxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgICBydWxlczogW3tcbiAgICAgICAgbmFtZTogXCJUb2tlbk1pbnRSYXRlTGltaXRcIixcbiAgICAgICAgcHJpb3JpdHk6IDAsXG4gICAgICAgIGFjdGlvbjoge1xuICAgICAgICAgIGJsb2NrOiB7XG4gICAgICAgICAgICBjdXN0b21SZXNwb25zZToge1xuICAgICAgICAgICAgICByZXNwb25zZUNvZGU6IDQyOSxcbiAgICAgICAgICAgICAgY3VzdG9tUmVzcG9uc2VCb2R5S2V5OiByYXRlTGltaXRCb2R5LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBzdGF0ZW1lbnQ6IHtcbiAgICAgICAgICByYXRlQmFzZWRTdGF0ZW1lbnQ6IHtcbiAgICAgICAgICAgIGxpbWl0OiAzMDAsXG4gICAgICAgICAgICBhZ2dyZWdhdGVLZXlUeXBlOiBcIklQXCIsXG4gICAgICAgICAgICBzY29wZURvd25TdGF0ZW1lbnQ6IHtcbiAgICAgICAgICAgICAgYnl0ZU1hdGNoU3RhdGVtZW50OiB7XG4gICAgICAgICAgICAgICAgZmllbGRUb01hdGNoOiB7IHVyaVBhdGg6IHt9IH0sXG4gICAgICAgICAgICAgICAgcG9zaXRpb25hbENvbnN0cmFpbnQ6IFwiU1RBUlRTX1dJVEhcIixcbiAgICAgICAgICAgICAgICBzZWFyY2hTdHJpbmc6IFwiL2FwaS90b2tlblwiLFxuICAgICAgICAgICAgICAgIHRleHRUcmFuc2Zvcm1hdGlvbnM6IFt7IHByaW9yaXR5OiAwLCB0eXBlOiBcIk5PTkVcIiB9XSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgdmlzaWJpbGl0eUNvbmZpZzoge1xuICAgICAgICAgIGNsb3VkV2F0Y2hNZXRyaWNzRW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICBtZXRyaWNOYW1lOiBgJHtBd3MuU1RBQ0tfTkFNRX0tdG9rZW4tcmF0ZS1saW1pdGAsXG4gICAgICAgICAgc2FtcGxlZFJlcXVlc3RzRW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgfSxcbiAgICAgIH1dLFxuICAgIH0pO1xuXG4gICAgLy8gRGVtbyB3ZWJzaXRlIChjb25kaXRpb25hbClcbiAgICBsZXQgZGlzdHJpYnV0aW9uOiBjbG91ZGZyb250LkRpc3RyaWJ1dGlvbjtcbiAgICBsZXQgZGVtb0J1Y2tldDogczMuQnVja2V0IHwgdW5kZWZpbmVkO1xuXG4gICAgaWYgKGNvbmZpZy5tYWluLmVuYWJsZURlbW8pIHtcbiAgICAgIGRlbW9CdWNrZXQgPSBuZXcgczMuQnVja2V0KHRoaXMsIFwiRGVtb1dlYnNpdGVcIiwge1xuICAgICAgICByZW1vdmFsUG9saWN5OiBSZW1vdmFsUG9saWN5LkRFU1RST1ksXG4gICAgICAgIGF1dG9EZWxldGVPYmplY3RzOiB0cnVlLFxuICAgICAgfSk7XG5cbiAgICAgIG5ldyBzM2RlcGxveS5CdWNrZXREZXBsb3ltZW50KHRoaXMsIFwiRGVwbG95RGVtb1NpdGVcIiwge1xuICAgICAgICBzb3VyY2VzOiBbczNkZXBsb3kuU291cmNlLmFzc2V0KFwicmVzb3VyY2VzL2RlbW8td2Vic2l0ZVwiKV0sXG4gICAgICAgIGRlc3RpbmF0aW9uQnVja2V0OiBkZW1vQnVja2V0LFxuICAgICAgICBkZXN0aW5hdGlvbktleVByZWZpeDogXCJ3ZWJzaXRlXCIsXG4gICAgICAgIHBydW5lOiBmYWxzZSxcbiAgICAgIH0pO1xuXG4gICAgICBkaXN0cmlidXRpb24gPSBuZXcgY2xvdWRmcm9udC5EaXN0cmlidXRpb24odGhpcywgXCJDVEFEaXN0cmlidXRpb25cIiwge1xuICAgICAgICB3ZWJBY2xJZDogd2ViQWNsLmF0dHJBcm4sXG4gICAgICAgIGRlZmF1bHRCZWhhdmlvcjoge1xuICAgICAgICAgIG9yaWdpbjogbmV3IEh0dHBPcmlnaW4oXCJjZG4ubWVkaWFwbGF5cGVuLmNvbVwiKSxcbiAgICAgICAgICB2aWV3ZXJQcm90b2NvbFBvbGljeTogY2xvdWRmcm9udC5WaWV3ZXJQcm90b2NvbFBvbGljeS5SRURJUkVDVF9UT19IVFRQUyxcbiAgICAgICAgICBjYWNoZVBvbGljeTogbmV3IGNsb3VkZnJvbnQuQ2FjaGVQb2xpY3kodGhpcywgXCJDVEFDYWNoZVBvbGljeVwiLCB7XG4gICAgICAgICAgICBoZWFkZXJCZWhhdmlvcjogY2xvdWRmcm9udC5DYWNoZUhlYWRlckJlaGF2aW9yLmFsbG93TGlzdChcbiAgICAgICAgICAgICAgXCJDbG91ZEZyb250LVZpZXdlci1Db3VudHJ5XCJcbiAgICAgICAgICAgICksXG4gICAgICAgICAgfSksXG4gICAgICAgICAgcmVzcG9uc2VIZWFkZXJzUG9saWN5OiBuZXcgY2xvdWRmcm9udC5SZXNwb25zZUhlYWRlcnNQb2xpY3kodGhpcywgXCJDVEFDb3JzUmVzcG9uc2VQb2xpY3lcIiwge1xuICAgICAgICAgICAgcmVzcG9uc2VIZWFkZXJzUG9saWN5TmFtZTogYCR7QXdzLlNUQUNLX05BTUV9LUNUQS1DT1JTYCxcbiAgICAgICAgICAgIGNvcnNCZWhhdmlvcjoge1xuICAgICAgICAgICAgICBhY2Nlc3NDb250cm9sQWxsb3dPcmlnaW5zOiBbXCIqXCJdLFxuICAgICAgICAgICAgICBhY2Nlc3NDb250cm9sQWxsb3dIZWFkZXJzOiBbXCJDVEEtQ29tbW9uLUFjY2Vzcy1Ub2tlblwiLCBcIkNvbnRlbnQtVHlwZVwiXSxcbiAgICAgICAgICAgICAgYWNjZXNzQ29udHJvbEFsbG93TWV0aG9kczogW1wiR0VUXCIsIFwiSEVBRFwiLCBcIk9QVElPTlNcIl0sXG4gICAgICAgICAgICAgIGFjY2Vzc0NvbnRyb2xFeHBvc2VIZWFkZXJzOiBbXCJDVEEtQ29tbW9uLUFjY2Vzcy1Ub2tlblwiXSxcbiAgICAgICAgICAgICAgYWNjZXNzQ29udHJvbEFsbG93Q3JlZGVudGlhbHM6IGZhbHNlLFxuICAgICAgICAgICAgICBhY2Nlc3NDb250cm9sTWF4QWdlOiBEdXJhdGlvbi5ob3VycygyNCksXG4gICAgICAgICAgICAgIG9yaWdpbk92ZXJyaWRlOiB0cnVlLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9KSxcbiAgICAgICAgICBvcmlnaW5SZXF1ZXN0UG9saWN5OiBjbG91ZGZyb250Lk9yaWdpblJlcXVlc3RQb2xpY3kuQUxMX1ZJRVdFUl9FWENFUFRfSE9TVF9IRUFERVIsXG4gICAgICAgICAgZnVuY3Rpb25Bc3NvY2lhdGlvbnM6IFt7XG4gICAgICAgICAgICBmdW5jdGlvbjogdmFsaWRhdG9yLFxuICAgICAgICAgICAgZXZlbnRUeXBlOiBjbG91ZGZyb250LkZ1bmN0aW9uRXZlbnRUeXBlLlZJRVdFUl9SRVFVRVNULFxuICAgICAgICAgIH1dLFxuICAgICAgICB9LFxuICAgICAgICBhZGRpdGlvbmFsQmVoYXZpb3JzOiB7XG4gICAgICAgICAgXCIvYXBpLypcIjoge1xuICAgICAgICAgICAgb3JpZ2luOiBuZXcgUmVzdEFwaU9yaWdpbihhcGkpLFxuICAgICAgICAgICAgdmlld2VyUHJvdG9jb2xQb2xpY3k6IGNsb3VkZnJvbnQuVmlld2VyUHJvdG9jb2xQb2xpY3kuUkVESVJFQ1RfVE9fSFRUUFMsXG4gICAgICAgICAgICBhbGxvd2VkTWV0aG9kczogY2xvdWRmcm9udC5BbGxvd2VkTWV0aG9kcy5BTExPV19BTEwsXG4gICAgICAgICAgICBjYWNoZVBvbGljeTogY2xvdWRmcm9udC5DYWNoZVBvbGljeS5DQUNISU5HX0RJU0FCTEVELFxuICAgICAgICAgICAgb3JpZ2luUmVxdWVzdFBvbGljeTogY2xvdWRmcm9udC5PcmlnaW5SZXF1ZXN0UG9saWN5LkFMTF9WSUVXRVJfRVhDRVBUX0hPU1RfSEVBREVSLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCIvd2Vic2l0ZS8qXCI6IHtcbiAgICAgICAgICAgIG9yaWdpbjogUzNCdWNrZXRPcmlnaW4ud2l0aE9yaWdpbkFjY2Vzc0NvbnRyb2woZGVtb0J1Y2tldCksXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuXG4gICAgfSBlbHNlIHtcbiAgICAgIGRpc3RyaWJ1dGlvbiA9IG5ldyBjbG91ZGZyb250LkRpc3RyaWJ1dGlvbih0aGlzLCBcIkNUQURpc3RyaWJ1dGlvblwiLCB7XG4gICAgICAgIHdlYkFjbElkOiB3ZWJBY2wuYXR0ckFybixcbiAgICAgICAgZGVmYXVsdEJlaGF2aW9yOiB7XG4gICAgICAgICAgb3JpZ2luOiBuZXcgUmVzdEFwaU9yaWdpbihhcGkpLFxuICAgICAgICAgIGZ1bmN0aW9uQXNzb2NpYXRpb25zOiBbe1xuICAgICAgICAgICAgZnVuY3Rpb246IHZhbGlkYXRvcixcbiAgICAgICAgICAgIGV2ZW50VHlwZTogY2xvdWRmcm9udC5GdW5jdGlvbkV2ZW50VHlwZS5WSUVXRVJfUkVRVUVTVCxcbiAgICAgICAgICB9XSxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHRoaXMuZGlzdHJpYnV0aW9uID0gZGlzdHJpYnV0aW9uO1xuICAgIGlmIChjb25maWcubWFpbi5lbmFibGVEZW1vKSB7XG4gICAgICB0aGlzLmRlbW9CdWNrZXQgPSBkZW1vQnVja2V0ITtcbiAgICB9XG5cbiAgICAvLyAtLS0gUmVhbC1UaW1lIExvZ2dpbmcgdmlhIEtpbmVzaXMgLS0tXG4gICAgY29uc3QgbG9nU3RyZWFtID0gbmV3IGtpbmVzaXMuU3RyZWFtKHRoaXMsIFwiUmVhbHRpbWVMb2dTdHJlYW1cIiwge1xuICAgICAgc3RyZWFtTW9kZToga2luZXNpcy5TdHJlYW1Nb2RlLk9OX0RFTUFORCxcbiAgICAgIHJldGVudGlvblBlcmlvZDogRHVyYXRpb24uaG91cnMoMjQpLFxuICAgIH0pO1xuICAgIHRoaXMubG9nU3RyZWFtID0gbG9nU3RyZWFtO1xuXG4gICAgY29uc3QgY2ZLaW5lc2lzUm9sZSA9IG5ldyBpYW0uUm9sZSh0aGlzLCBcIkNsb3VkRnJvbnRLaW5lc2lzUm9sZVwiLCB7XG4gICAgICBhc3N1bWVkQnk6IG5ldyBpYW0uU2VydmljZVByaW5jaXBhbChcImNsb3VkZnJvbnQuYW1hem9uYXdzLmNvbVwiKSxcbiAgICB9KTtcbiAgICBsb2dTdHJlYW0uZ3JhbnRXcml0ZShjZktpbmVzaXNSb2xlKTtcblxuICAgIGNvbnN0IHJlYWx0aW1lTG9nQ29uZmlnID0gbmV3IGNsb3VkZnJvbnQuQ2ZuUmVhbHRpbWVMb2dDb25maWcodGhpcywgXCJSZWFsdGltZUxvZ0NvbmZpZ1wiLCB7XG4gICAgICBuYW1lOiBgJHtBd3MuU1RBQ0tfTkFNRX0tcmVhbHRpbWUtbG9nc2AsXG4gICAgICBzYW1wbGluZ1JhdGU6IDEwMCxcbiAgICAgIGVuZFBvaW50czogW3tcbiAgICAgICAgc3RyZWFtVHlwZTogXCJLaW5lc2lzXCIsXG4gICAgICAgIGtpbmVzaXNTdHJlYW1Db25maWc6IHtcbiAgICAgICAgICByb2xlQXJuOiBjZktpbmVzaXNSb2xlLnJvbGVBcm4sXG4gICAgICAgICAgc3RyZWFtQXJuOiBsb2dTdHJlYW0uc3RyZWFtQXJuLFxuICAgICAgICB9LFxuICAgICAgfV0sXG4gICAgICBmaWVsZHM6IFtcbiAgICAgICAgXCJ0aW1lc3RhbXBcIiwgXCJjLWlwXCIsIFwic2Mtc3RhdHVzXCIsIFwiY3MtdXJpLXN0ZW1cIiwgXCJjcy1tZXRob2RcIixcbiAgICAgICAgXCJjcy1ob3N0XCIsIFwiY3MtdXNlci1hZ2VudFwiLCBcInNjLWJ5dGVzXCIsIFwidGltZS10YWtlblwiLCBcImMtY291bnRyeVwiLFxuICAgICAgXSxcbiAgICB9KTtcblxuICAgIC8vIEF0dGFjaCByZWFsLXRpbWUgbG9ncyB0byB0aGUgZGVmYXVsdCBjYWNoZSBiZWhhdmlvclxuICAgIGNvbnN0IGNmbkRpc3QgPSBkaXN0cmlidXRpb24ubm9kZS5kZWZhdWx0Q2hpbGQgYXMgY2xvdWRmcm9udC5DZm5EaXN0cmlidXRpb247XG4gICAgY2ZuRGlzdC5hZGRQcm9wZXJ0eU92ZXJyaWRlKFxuICAgICAgXCJEaXN0cmlidXRpb25Db25maWcuRGVmYXVsdENhY2hlQmVoYXZpb3IuUmVhbHRpbWVMb2dDb25maWdBcm5cIixcbiAgICAgIHJlYWx0aW1lTG9nQ29uZmlnLmF0dHJBcm5cbiAgICApO1xuXG4gICAgLy8gLS0tIERhc2hib2FyZDogbGlzdCByZXZva2VkIHNlc3Npb25zIGZyb20gS1ZTIC0tLVxuICAgIGNvbnN0IGxpc3RSZXZva2VkID0gbmV3IGxhbWJkYS5GdW5jdGlvbih0aGlzLCBcIkxpc3RSZXZva2VkXCIsIHtcbiAgICAgIHJ1bnRpbWU6IGxhbWJkYS5SdW50aW1lLk5PREVKU18yMl9YLFxuICAgICAgaGFuZGxlcjogXCJsaXN0X3Jldm9rZWQuaGFuZGxlclwiLFxuICAgICAgY29kZTogbGFtYmRhLkNvZGUuZnJvbUFzc2V0KFwibGFtYmRhXCIpLFxuICAgICAgdGltZW91dDogRHVyYXRpb24uc2Vjb25kcygxMCksXG4gICAgICBlbnZpcm9ubWVudDogeyBLVlNfQVJOOiB0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUFybiB9LFxuICAgIH0pO1xuICAgIGxpc3RSZXZva2VkLmFkZFRvUm9sZVBvbGljeShuZXcgaWFtLlBvbGljeVN0YXRlbWVudCh7XG4gICAgICBhY3Rpb25zOiBbXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6TGlzdEtleXNcIiwgXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6RGVzY3JpYmVLZXlWYWx1ZVN0b3JlXCJdLFxuICAgICAgcmVzb3VyY2VzOiBbdGhpcy5rdlN0b3JlLmtleVZhbHVlU3RvcmVBcm5dLFxuICAgIH0pKTtcblxuICAgIC8vIEFkZCAvcmV2b2tlZCB0byB0aGUgZXhpc3RpbmcgQVBJXG4gICAgYXBpLnJvb3QuYWRkUmVzb3VyY2UoXCJyZXZva2VkXCIpLmFkZE1ldGhvZChcIkdFVFwiLFxuICAgICAgbmV3IGFwaWdhdGV3YXkuTGFtYmRhSW50ZWdyYXRpb24obGlzdFJldm9rZWQpXG4gICAgKTtcblxuICAgIC8vIERlcGxveSBkYXNoYm9hcmQgSFRNTCAoYWxvbmdzaWRlIGRlbW8gc2l0ZSBpZiBlbmFibGVkKVxuICAgIGlmIChjb25maWcubWFpbi5lbmFibGVEZW1vKSB7XG4gICAgICBuZXcgczNkZXBsb3kuQnVja2V0RGVwbG95bWVudCh0aGlzLCBcIkRlcGxveURhc2hib2FyZFwiLCB7XG4gICAgICAgIHNvdXJjZXM6IFtcbiAgICAgICAgICBzM2RlcGxveS5Tb3VyY2UuYXNzZXQoXCJyZXNvdXJjZXMvZGFzaGJvYXJkXCIpLFxuICAgICAgICAgIHMzZGVwbG95LlNvdXJjZS5kYXRhKFwiY29uZmlnLmpzXCIsXG4gICAgICAgICAgICBgd2luZG93LkNUQV9DT05GSUc9e2FwaUVuZHBvaW50OlwiJHthcGkudXJsLnJlcGxhY2UoL1xcLyQvLCcnKX1cIixjZG5Eb21haW46XCJodHRwczovLyR7ZGlzdHJpYnV0aW9uLmRpc3RyaWJ1dGlvbkRvbWFpbk5hbWV9XCJ9O2BcbiAgICAgICAgICApLFxuICAgICAgICBdLFxuICAgICAgICBkZXN0aW5hdGlvbkJ1Y2tldDogZGVtb0J1Y2tldCEsXG4gICAgICAgIGRlc3RpbmF0aW9uS2V5UHJlZml4OiBcIndlYnNpdGVcIixcbiAgICAgICAgcHJ1bmU6IGZhbHNlLFxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLy8gLS0tIEtWUyBDbGVhbnVwOiBwdXJnZSBleHBpcmVkIHJldm9jYXRpb25zIG9uIGEgc2NoZWR1bGUgLS0tXG4gICAgY29uc3Qga3ZzQ2xlYW51cCA9IG5ldyBsYW1iZGEuRnVuY3Rpb24odGhpcywgXCJLdnNDbGVhbnVwXCIsIHtcbiAgICAgIHJ1bnRpbWU6IGxhbWJkYS5SdW50aW1lLk5PREVKU18yMl9YLFxuICAgICAgaGFuZGxlcjogXCJrdnNfY2xlYW51cC5oYW5kbGVyXCIsXG4gICAgICBjb2RlOiBsYW1iZGEuQ29kZS5mcm9tQXNzZXQoXCJsYW1iZGFcIiksXG4gICAgICB0aW1lb3V0OiBEdXJhdGlvbi5taW51dGVzKDIpLFxuICAgICAgZW52aXJvbm1lbnQ6IHsgS1ZTX0FSTjogdGhpcy5rdlN0b3JlLmtleVZhbHVlU3RvcmVBcm4sIFRUTF9IT1VSUzogXCIyNFwiIH0sXG4gICAgfSk7XG4gICAga3ZzQ2xlYW51cC5hZGRUb1JvbGVQb2xpY3kobmV3IGlhbS5Qb2xpY3lTdGF0ZW1lbnQoe1xuICAgICAgYWN0aW9uczogW1wiY2xvdWRmcm9udC1rZXl2YWx1ZXN0b3JlOkxpc3RLZXlzXCIsIFwiY2xvdWRmcm9udC1rZXl2YWx1ZXN0b3JlOkRlbGV0ZUtleVwiLCBcImNsb3VkZnJvbnQta2V5dmFsdWVzdG9yZTpEZXNjcmliZUtleVZhbHVlU3RvcmVcIl0sXG4gICAgICByZXNvdXJjZXM6IFt0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUFybl0sXG4gICAgfSkpO1xuICAgIG5ldyBldmVudHMuUnVsZSh0aGlzLCBcIkt2c0NsZWFudXBTY2hlZHVsZVwiLCB7XG4gICAgICBzY2hlZHVsZTogZXZlbnRzLlNjaGVkdWxlLnJhdGUoRHVyYXRpb24uaG91cnMoMSkpLFxuICAgICAgdGFyZ2V0czogW25ldyB0YXJnZXRzLkxhbWJkYUZ1bmN0aW9uKGt2c0NsZWFudXApXSxcbiAgICB9KTtcblxuICAgIC8vIE91dHB1dHNcbiAgICBuZXcgQ2ZuT3V0cHV0KHRoaXMsIFwiQVBJRW5kcG9pbnRcIiwgeyBcbiAgICAgIHZhbHVlOiBgaHR0cHM6Ly8ke2Rpc3RyaWJ1dGlvbi5kaXN0cmlidXRpb25Eb21haW5OYW1lfS9hcGlgLFxuICAgICAgZGVzY3JpcHRpb246IFwiQ1RBIEFQSSBFbmRwb2ludFwiXG4gICAgfSk7XG4gICAgXG4gICAgaWYgKGNvbmZpZy5tYWluLmVuYWJsZURlbW8pIHtcbiAgICAgIG5ldyBDZm5PdXRwdXQodGhpcywgXCJEZW1vV2Vic2l0ZVVybFwiLCB7IFxuICAgICAgICB2YWx1ZTogYGh0dHBzOi8vJHtkaXN0cmlidXRpb24uZGlzdHJpYnV0aW9uRG9tYWluTmFtZX0vd2Vic2l0ZS9pbmRleC1wYXRoLmh0bWxgLFxuICAgICAgICBkZXNjcmlwdGlvbjogXCJDVEEgRGVtbyBXZWJzaXRlIOKAlCBQYXRoIFRva2VuIE1vZGVcIlxuICAgICAgfSk7XG4gICAgICBuZXcgQ2ZuT3V0cHV0KHRoaXMsIFwiRGVtb1dlYnNpdGVIZWFkZXJVcmxcIiwgeyBcbiAgICAgICAgdmFsdWU6IGBodHRwczovLyR7ZGlzdHJpYnV0aW9uLmRpc3RyaWJ1dGlvbkRvbWFpbk5hbWV9L3dlYnNpdGUvaW5kZXgtaGVhZGVyLmh0bWxgLFxuICAgICAgICBkZXNjcmlwdGlvbjogXCJDVEEgRGVtbyBXZWJzaXRlIOKAlCBIZWFkZXItT25seSBUb2tlbiBNb2RlXCJcbiAgICAgIH0pO1xuICAgICAgbmV3IENmbk91dHB1dCh0aGlzLCBcIkRlbW9XZWJzaXRlSHlicmlkVXJsXCIsIHsgXG4gICAgICAgIHZhbHVlOiBgaHR0cHM6Ly8ke2Rpc3RyaWJ1dGlvbi5kaXN0cmlidXRpb25Eb21haW5OYW1lfS93ZWJzaXRlL2luZGV4LWh5YnJpZC5odG1sYCxcbiAgICAgICAgZGVzY3JpcHRpb246IFwiQ1RBIERlbW8gV2Vic2l0ZSDigJQgSHlicmlkIChQYXRoIEluaXQg4oaSIEhlYWRlciBSZW5ld2FsKVwiXG4gICAgICB9KTtcbiAgICAgIG5ldyBDZm5PdXRwdXQodGhpcywgXCJEYXNoYm9hcmRVcmxcIiwgeyBcbiAgICAgICAgdmFsdWU6IGBodHRwczovLyR7ZGlzdHJpYnV0aW9uLmRpc3RyaWJ1dGlvbkRvbWFpbk5hbWV9L3dlYnNpdGUvZGFzaGJvYXJkLmh0bWxgLFxuICAgICAgICBkZXNjcmlwdGlvbjogXCJSZXZvY2F0aW9uIERhc2hib2FyZCB3aXRoIEJlZHJvY2sgUHJvbXB0IEVkaXRvclwiXG4gICAgICB9KTtcbiAgICB9XG4gICAgXG4gICAgbmV3IENmbk91dHB1dCh0aGlzLCBcIktleVZhbHVlU3RvcmVJZFwiLCB7IFxuICAgICAgdmFsdWU6IHRoaXMua3ZTdG9yZS5rZXlWYWx1ZVN0b3JlSWQsXG4gICAgICBkZXNjcmlwdGlvbjogXCJDbG91ZEZyb250IEtleVZhbHVlU3RvcmUgSURcIlxuICAgIH0pO1xuXG4gICAgbmV3IENmbk91dHB1dCh0aGlzLCBcIlNlY3JldEFyblwiLCB7XG4gICAgICB2YWx1ZTogc2lnbmluZ1NlY3JldC5zZWNyZXRBcm4sXG4gICAgICBkZXNjcmlwdGlvbjogXCJDVEEgc2lnbmluZyBzZWNyZXQgQVJOXCJcbiAgICB9KTtcblxuICAgIG5ldyBDZm5PdXRwdXQodGhpcywgXCJDVEFTdGFuZGFyZFwiLCB7XG4gICAgICB2YWx1ZTogXCJDVEEtNTAwNy1CXCIsXG4gICAgICBkZXNjcmlwdGlvbjogXCJJbXBsZW1lbnRlZCBzdGFuZGFyZCB2ZXJzaW9uXCJcbiAgICB9KTtcblxuICAgIG5ldyBDZm5PdXRwdXQodGhpcywgXCJSb3RhdGlvbldvcmtmbG93XCIsIHtcbiAgICAgIHZhbHVlOiByb3RhdGlvbldvcmtmbG93LnN0YXRlTWFjaGluZU5hbWUsXG4gICAgICBkZXNjcmlwdGlvbjogXCJLZXkgcm90YXRpb24gU3RlcCBGdW5jdGlvbnMgd29ya2Zsb3dcIlxuICAgIH0pO1xuXG4gICAgbmV3IENmbk91dHB1dCh0aGlzLCBcIldlYkFjbEFyblwiLCB7XG4gICAgICB2YWx1ZTogd2ViQWNsLmF0dHJBcm4sXG4gICAgICBkZXNjcmlwdGlvbjogXCJXQUZ2MiBXZWIgQUNMIOKAlCByYXRlLWxpbWl0cyBQT1NUIC9hcGkvdG9rZW5cIlxuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBwYXJzZVJvdGF0aW9uUmF0ZShyYXRlOiBzdHJpbmcpOiBEdXJhdGlvbiB7XG4gICAgY29uc3QgbWF0Y2ggPSByYXRlLm1hdGNoKC9eKFxcZCspKFttaGRdKSQvKTtcbiAgICBpZiAoIW1hdGNoKSByZXR1cm4gRHVyYXRpb24uZGF5cygzMCk7XG4gICAgY29uc3QgdmFsdWUgPSBwYXJzZUludChtYXRjaFsxXSk7XG4gICAgc3dpdGNoIChtYXRjaFsyXSkge1xuICAgICAgY2FzZSAnbSc6IHJldHVybiBEdXJhdGlvbi5taW51dGVzKHZhbHVlKTtcbiAgICAgIGNhc2UgJ2gnOiByZXR1cm4gRHVyYXRpb24uaG91cnModmFsdWUpO1xuICAgICAgY2FzZSAnZCc6IHJldHVybiBEdXJhdGlvbi5kYXlzKHZhbHVlKTtcbiAgICAgIGRlZmF1bHQ6IHJldHVybiBEdXJhdGlvbi5kYXlzKDMwKTtcbiAgICB9XG4gIH1cbn1cbiJdfQ==