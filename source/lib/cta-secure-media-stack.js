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
        const rotationOverlap = Number(config.main.rotationOverlapSeconds ?? 7200);
        const rotationPropagation = Number(config.main.rotationPropagationSeconds ?? 300);
        if (!Number.isSafeInteger(rotationOverlap) || rotationOverlap < 7200 ||
            !Number.isSafeInteger(rotationPropagation) || rotationPropagation < 300) {
            throw new Error("Rotation requires integer overlap >=7200s and propagation >=300s");
        }
        if (rotationPropagation + rotationOverlap + 60 + 60 > 31449600) {
            throw new Error("Rotation propagation + overlap + 60s mint cache + 60s in-flight allowance must not exceed 31449600s (364 days), reserving one day for workflow tasks and retries");
        }
        const syncKeysToKvs = new aws_cdk_lib_1.aws_lambda.Function(this, "SyncKeysToKvs", {
            runtime: aws_cdk_lib_1.aws_lambda.Runtime.NODEJS_22_X,
            handler: "index.handler",
            code: aws_cdk_lib_1.aws_lambda.Code.fromAsset("lambda/sync_keys"),
            timeout: aws_cdk_lib_1.Duration.seconds(30),
            environment: {
                SECRET_NAME: signingSecret.secretName,
                KVS_ARN: this.kvStore.keyValueStoreArn,
                ROTATION_OVERLAP_SECONDS: String(rotationOverlap),
                ROTATION_PROPAGATION_SECONDS: String(rotationPropagation),
            },
        });
        signingSecret.grantRead(syncKeysToKvs);
        signingSecret.grantWrite(syncKeysToKvs);
        syncKeysToKvs.addToRolePolicy(new aws_cdk_lib_1.aws_iam.PolicyStatement({
            effect: aws_cdk_lib_1.aws_iam.Effect.ALLOW,
            actions: [
                "cloudfront-keyvaluestore:GetKey",
                "cloudfront-keyvaluestore:UpdateKeys",
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
        // Durable, execution-owned rotation. Only metadata enters workflow history.
        const rotationTask = (id, action) => {
            const task = new aws_cdk_lib_1.aws_stepfunctions_tasks.LambdaInvoke(this, id, {
                lambdaFunction: syncKeysToKvs,
                payload: aws_cdk_lib_1.aws_stepfunctions.TaskInput.fromObject({
                    action,
                    executionId: aws_cdk_lib_1.aws_stepfunctions.JsonPath.stringAt("$$.Execution.Id"),
                }),
                resultPath: "$.rotation",
            });
            task.addRetry({ errors: ["States.TaskFailed"], interval: aws_cdk_lib_1.Duration.seconds(2), maxAttempts: 6, backoffRate: 2 });
            return task;
        };
        const prepareKey = rotationTask("PrepareSigningKey", "prepare");
        const waitForEdge = new aws_cdk_lib_1.aws_stepfunctions.Wait(this, "WaitForEdgePropagation", {
            time: aws_cdk_lib_1.aws_stepfunctions.WaitTime.timestampPath("$.rotation.Payload.propagationReadyTimestamp"),
        });
        const promoteKey = rotationTask("PromoteMintKey", "promote");
        const finalizeOverlap = rotationTask("FinalizeOverlap", "finalize");
        const waitForOverlap = new aws_cdk_lib_1.aws_stepfunctions.Wait(this, "WaitForOverlap", {
            time: aws_cdk_lib_1.aws_stepfunctions.WaitTime.timestampPath("$.rotation.Payload.cleanupTimestamp"),
        });
        const cleanupKey = rotationTask("RemovePreviousKey", "cleanup");
        const rotationWorkflow = new aws_cdk_lib_1.aws_stepfunctions.StateMachine(this, "KeyRotationWorkflow", {
            stateMachineName: `${aws_cdk_lib_1.Aws.STACK_NAME}_RotateKeys`,
            definitionBody: aws_cdk_lib_1.aws_stepfunctions.DefinitionBody.fromChainable(prepareKey.next(waitForEdge).next(promoteKey).next(finalizeOverlap).next(waitForOverlap).next(cleanupKey)),
        });
        // Keep disabled until the updated validators and mints are verified.
        const rotationSchedule = config.main.rotationFrequency || "30d";
        const rotationRate = this.parseRotationRate(rotationSchedule);
        new aws_cdk_lib_1.aws_events.Rule(this, "KeyRotationSchedule", {
            schedule: aws_cdk_lib_1.aws_events.Schedule.rate(rotationRate),
            enabled: config.main.rotationEnabled === true,
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY3RhLXNlY3VyZS1tZWRpYS1zdGFjay5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbImN0YS1zZWN1cmUtbWVkaWEtc3RhY2sudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsNkNBdUJxQjtBQUVyQiwrRUFBK0Y7QUFDL0YscUVBQStEO0FBTy9ELE1BQWEsbUJBQW9CLFNBQVEsbUJBQUs7SUFNNUMsWUFBWSxLQUFnQixFQUFFLEVBQVUsRUFBRSxRQUFrQyxFQUFFO1FBQzVFLEtBQUssQ0FBQyxLQUFLLEVBQUUsRUFBRSxFQUFFLEtBQUssQ0FBQyxDQUFDO1FBRXhCLE1BQU0sVUFBVSxHQUFHLElBQUksMEJBQVksQ0FBQyxJQUFJLEVBQUUsWUFBWSxFQUFFO1lBQ3RELElBQUksRUFBRSxRQUFRO1lBQ2QsT0FBTyxFQUFFLE1BQU07WUFDZixhQUFhLEVBQUUsQ0FBQyxNQUFNLEVBQUUsT0FBTyxDQUFDO1lBQ2hDLFdBQVcsRUFBRSxxQkFBcUI7U0FDbkMsQ0FBQyxDQUFDO1FBRUgsTUFBTSxZQUFZLEdBQUcsSUFBSSwwQkFBWSxDQUFDLElBQUksRUFBRSxjQUFjLEVBQUU7WUFDMUQsSUFBSSxFQUFFLFFBQVE7WUFDZCxPQUFPLEVBQUUsdUJBQXVCO1lBQ2hDLGFBQWEsRUFBRSxDQUFDLHNCQUFzQixFQUFFLHVCQUF1QixDQUFDO1lBQ2hFLFdBQVcsRUFBRSwrQkFBK0I7U0FDN0MsQ0FBQyxDQUFDO1FBRUgsTUFBTSxNQUFNLEdBQUcsS0FBSyxDQUFDLE1BQU0sSUFBSTtZQUM3QixJQUFJLEVBQUU7Z0JBQ0osVUFBVSxFQUFFLFVBQVUsQ0FBQyxhQUFhLEtBQUssTUFBTTthQUNoRDtZQUNELE9BQU8sRUFBRTtnQkFDUCxLQUFLLEVBQUUsWUFBWSxDQUFDLGFBQWE7YUFDbEM7U0FDRixDQUFDO1FBRUYsa0JBQWtCO1FBQ2xCLE1BQU0sYUFBYSxHQUFHLElBQUksZ0NBQWMsQ0FBQyxNQUFNLENBQUMsSUFBSSxFQUFFLFFBQVEsRUFBRTtZQUM5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Q0FBQyxDQUFDO1FBQ3JDLE1BQU0sS0FBSyxHQUFHLFFBQVEsQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztRQUNqQyxRQUFRLEtBQUssQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDO1lBQ2pCLEtBQUssR0FBRyxDQUFDLENBQUMsT0FBTyxzQkFBUSxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUN6QyxLQUFLLEdBQUcsQ0FBQyxDQUFDLE9BQU8sc0JBQVEsQ0FBQyxLQUFLLENBQUMsS0FBSyxDQUFDLENBQUM7WUFDdkMsS0FBSyxHQUFHLENBQUMsQ0FBQyxPQUFPLHNCQUFRLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDO1lBQ3RDLE9BQU8sQ0FBQyxDQUFDLE9BQU8sc0JBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFDLENBQUM7UUFDcEMsQ0FBQztJQUNILENBQUM7Q0FDRjtBQTlnQkQsa0RBOGdCQyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7XG4gIFN0YWNrLFxuICBTdGFja1Byb3BzLFxuICBBd3MsXG4gIFJlbW92YWxQb2xpY3ksXG4gIER1cmF0aW9uLFxuICBDZm5PdXRwdXQsXG4gIENmblBhcmFtZXRlcixcbiAgQ3VzdG9tUmVzb3VyY2UsXG4gIGF3c19jbG91ZGZyb250IGFzIGNsb3VkZnJvbnQsXG4gIGF3c19sYW1iZGEgYXMgbGFtYmRhLFxuICBhd3NfYXBpZ2F0ZXdheSBhcyBhcGlnYXRld2F5LFxuICBhd3Nfc2VjcmV0c21hbmFnZXIgYXMgc2VjcmV0c21hbmFnZXIsXG4gIGF3c19zMyBhcyBzMyxcbiAgYXdzX3MzX2RlcGxveW1lbnQgYXMgczNkZXBsb3ksXG4gIGF3c19pYW0gYXMgaWFtLFxuICBhd3Nfc3RlcGZ1bmN0aW9ucyBhcyBzZm4sXG4gIGF3c19zdGVwZnVuY3Rpb25zX3Rhc2tzIGFzIHRhc2tzLFxuICBhd3NfZXZlbnRzIGFzIGV2ZW50cyxcbiAgYXdzX2V2ZW50c190YXJnZXRzIGFzIHRhcmdldHMsXG4gIGF3c19raW5lc2lzIGFzIGtpbmVzaXMsXG4gIGF3c193YWZ2MiBhcyB3YWZ2MixcbiAgY3VzdG9tX3Jlc291cmNlcyxcbn0gZnJvbSBcImF3cy1jZGstbGliXCI7XG5cbmltcG9ydCB7IEh0dHBPcmlnaW4sIFJlc3RBcGlPcmlnaW4sIFMzQnVja2V0T3JpZ2luIH0gZnJvbSBcImF3cy1jZGstbGliL2F3cy1jbG91ZGZyb250LW9yaWdpbnNcIjtcbmltcG9ydCB7IE5vZGVqc0Z1bmN0aW9uIH0gZnJvbSBcImF3cy1jZGstbGliL2F3cy1sYW1iZGEtbm9kZWpzXCI7XG5pbXBvcnQgeyBDb25zdHJ1Y3QgfSBmcm9tIFwiY29uc3RydWN0c1wiO1xuXG5leHBvcnQgaW50ZXJmYWNlIENUQVNlY3VyZU1lZGlhU3RhY2tQcm9wcyBleHRlbmRzIFN0YWNrUHJvcHMge1xuICByZWFkb25seSBjb25maWc/OiBhbnk7XG59XG5cbmV4cG9ydCBjbGFzcyBDVEFTZWN1cmVNZWRpYVN0YWNrIGV4dGVuZHMgU3RhY2sge1xuICBwdWJsaWMgcmVhZG9ubHkga3ZTdG9yZTogY2xvdWRmcm9udC5LZXlWYWx1ZVN0b3JlO1xuICBwdWJsaWMgcmVhZG9ubHkgZGlzdHJpYnV0aW9uOiBjbG91ZGZyb250LkRpc3RyaWJ1dGlvbjtcbiAgcHVibGljIHJlYWRvbmx5IGRlbW9CdWNrZXQ6IHMzLkJ1Y2tldDtcbiAgcHVibGljIHJlYWRvbmx5IGxvZ1N0cmVhbToga2luZXNpcy5TdHJlYW07XG4gIFxuICBjb25zdHJ1Y3RvcihzY29wZTogQ29uc3RydWN0LCBpZDogc3RyaW5nLCBwcm9wczogQ1RBU2VjdXJlTWVkaWFTdGFja1Byb3BzID0ge30pIHtcbiAgICBzdXBlcihzY29wZSwgaWQsIHByb3BzKTtcblxuICAgIGNvbnN0IGVuYWJsZURlbW8gPSBuZXcgQ2ZuUGFyYW1ldGVyKHRoaXMsIFwiRW5hYmxlRGVtb1wiLCB7XG4gICAgICB0eXBlOiBcIlN0cmluZ1wiLFxuICAgICAgZGVmYXVsdDogXCJ0cnVlXCIsXG4gICAgICBhbGxvd2VkVmFsdWVzOiBbXCJ0cnVlXCIsIFwiZmFsc2VcIl0sXG4gICAgICBkZXNjcmlwdGlvbjogXCJEZXBsb3kgZGVtbyB3ZWJzaXRlXCIsXG4gICAgfSk7XG5cbiAgICBjb25zdCBiZWRyb2NrTW9kZWwgPSBuZXcgQ2ZuUGFyYW1ldGVyKHRoaXMsIFwiQmVkcm9ja01vZGVsXCIsIHtcbiAgICAgIHR5cGU6IFwiU3RyaW5nXCIsXG4gICAgICBkZWZhdWx0OiBcImFtYXpvbi5ub3ZhLWxpdGUtdjE6MFwiLFxuICAgICAgYWxsb3dlZFZhbHVlczogW1wiYW1hem9uLm5vdmEtcHJvLXYxOjBcIiwgXCJhbWF6b24ubm92YS1saXRlLXYxOjBcIl0sXG4gICAgICBkZXNjcmlwdGlvbjogXCJCZWRyb2NrIG1vZGVsIGZvciBBSSBhbmFseXNpc1wiLFxuICAgIH0pO1xuXG4gICAgY29uc3QgY29uZmlnID0gcHJvcHMuY29uZmlnIHx8IHtcbiAgICAgIG1haW46IHtcbiAgICAgICAgZW5hYmxlRGVtbzogZW5hYmxlRGVtby52YWx1ZUFzU3RyaW5nID09PSBcInRydWVcIixcbiAgICAgIH0sXG4gICAgICBiZWRyb2NrOiB7XG4gICAgICAgIG1vZGVsOiBiZWRyb2NrTW9kZWwudmFsdWVBc1N0cmluZyxcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgLy8gQ1RBIHNpZ25pbmcga2V5XG4gICAgY29uc3Qgc2lnbmluZ1NlY3JldCA9IG5ldyBzZWNyZXRzbWFuYWdlci5TZWNyZXQodGhpcywgXCJDVEFLZXlcIiwge1xuICAgICAgZ2VuZXJhdGVTZWNyZXRTdHJpbmc6IHtcbiAgICAgICAgc2VjcmV0U3RyaW5nVGVtcGxhdGU6ICd7XCJhbGdvcml0aG1cIjpcIkhNQUMtU0hBMjU2XCJ9JyxcbiAgICAgICAgZ2VuZXJhdGVTdHJpbmdLZXk6IFwic2lnbmluZ0tleVwiLFxuICAgICAgICBwYXNzd29yZExlbmd0aDogNjQsXG4gICAgICB9LFxuICAgICAgcmVtb3ZhbFBvbGljeTogUmVtb3ZhbFBvbGljeS5ERVNUUk9ZLFxuICAgIH0pO1xuXG4gICAgLy8gQ2xvdWRGcm9udCBLZXlWYWx1ZVN0b3JlIGZvciByZXZvY2F0aW9uXG4gICAgdGhpcy5rdlN0b3JlID0gbmV3IGNsb3VkZnJvbnQuS2V5VmFsdWVTdG9yZSh0aGlzLCBcIkNUQVJldm9jYXRpb25TdG9yZVwiLCB7XG4gICAgICBjb21tZW50OiBcIkNUQSB0b2tlbiByZXZvY2F0aW9uIGxpc3RcIixcbiAgICB9KTtcblxuICAgIC8vIENUQSB2YWxpZGF0b3IgZnVuY3Rpb24uXG4gICAgLy9cbiAgICAvLyBFeHBsaWNpdCBhZGREZXBlbmRlbmN5IG9uIHRoZSBLVlM6IENsb3VkRnJvbnQgS2V5VmFsdWVTdG9yZSBpcyBhXG4gICAgLy8gdHdvLXBoYXNlIEFXUyByZXNvdXJjZSAoUHJvdmlzaW9uaW5nIC0+IFJlYWR5KS4gVGhlIEwyIGNvbnN0cnVjdFxuICAgIC8vIHJldHVybnMgdGhlIEFSTiBiZWZvcmUgdGhlIHN0b3JlIGlzIFJlYWR5LCBzbyB3aXRob3V0IHRoaXNcbiAgICAvLyBkZXBlbmRlbmN5IENESyBjYW4gb3JkZXIgdGhlIENGIEZ1bmN0aW9uJ3MgS2V5VmFsdWVTdG9yZUFzc29jaWF0aW9uc1xuICAgIC8vIGJlZm9yZSB0aGUgS1ZTIGlzIFJlYWR5IGFuZCBDbG91ZEZvcm1hdGlvbiBmYWlscyB3aXRoOlxuICAgIC8vICAgXCJjYW5ub3QgYmUgYXNzb2NpYXRlZCBiZWZvcmUgdGhlIHJlc291cmNlIGlzIHByb3Zpc2lvbmVkXCJcbiAgICAvLyBUaGUgZmFpbHVyZSBpcyBpbnRlcm1pdHRlbnQg4oCUIGl0IGRlcGVuZHMgb24gQ0RLJ3MgZ3JhcGggdHJhdmVyc2FsXG4gICAgLy8gb3JkZXIg4oCUIHdoaWNoIG1ha2VzIGl0IGVzcGVjaWFsbHkgZnJ1c3RyYXRpbmcgdG8gZGVidWcgb24gYSBmcmVzaFxuICAgIC8vIGRlcGxveS5cbiAgICBjb25zdCB2YWxpZGF0b3IgPSBuZXcgY2xvdWRmcm9udC5GdW5jdGlvbih0aGlzLCBcIkNUQVZhbGlkYXRvclwiLCB7XG4gICAgICBjb2RlOiBjbG91ZGZyb250LkZ1bmN0aW9uQ29kZS5mcm9tRmlsZSh7IGZpbGVQYXRoOiBcImxhbWJkYS9jdGFfdG9rZW5fdmFsaWRhdG9yLmpzXCIgfSksXG4gICAgICBmdW5jdGlvbk5hbWU6IGAke0F3cy5TVEFDS19OQU1FfS1DVEEtVmFsaWRhdG9yYCxcbiAgICAgIHJ1bnRpbWU6IGNsb3VkZnJvbnQuRnVuY3Rpb25SdW50aW1lLkpTXzJfMCxcbiAgICAgIGtleVZhbHVlU3RvcmU6IHRoaXMua3ZTdG9yZSxcbiAgICB9KTtcbiAgICB2YWxpZGF0b3Iubm9kZS5hZGREZXBlbmRlbmN5KHRoaXMua3ZTdG9yZSk7XG5cbiAgICAvLyBUb2tlbiBnZW5lcmF0b3IgKE5vZGUgU0RLKVxuICAgIC8vIE5vZGVqc0Z1bmN0aW9uIChlc2J1aWxkKSBidW5kbGVzIHRoZSBoYW5kbGVyIHRvZ2V0aGVyIHdpdGggaXRzXG4gICAgLy8gdGhpcmQtcGFydHkgZGVwZW5kZW5jeSBjYm9yLXgsIHdoaWNoIGlzIE5PVCBwcm92aWRlZCBieSB0aGUgTGFtYmRhXG4gICAgLy8gTm9kZS5qcyBydW50aW1lLiBBIHBsYWluIENvZGUuZnJvbUFzc2V0KFwibGFtYmRhXCIpIHNoaXBzIG5vIG5vZGVfbW9kdWxlcyxcbiAgICAvLyBzbyByZXF1aXJlKCdjYm9yLXgnKSBmYWlscyBhdCBtb2R1bGUgaW5pdCBhbmQgQVBJIEdhdGV3YXkgcmV0dXJucyBhIDUwMlxuICAgIC8vIHdpdGggbm8gQ09SUyBoZWFkZXJzIOKAlCBzdXJmYWNpbmcgaW4gdGhlIGJyb3dzZXIgYXMgYSBDT1JTIGVycm9yLlxuICAgIC8vIFRoZSBBV1MgU0RLIHYzIHBhY2thZ2VzIChAYXdzLXNkay8qKSByZW1haW4gZXh0ZXJuYWxpemVkIGJ5IGRlZmF1bHRcbiAgICAvLyBzaW5jZSB0aGV5IEFSRSBwcmVzZW50IGluIHRoZSBydW50aW1lLlxuICAgIGNvbnN0IGdlbmVyYXRvciA9IG5ldyBOb2RlanNGdW5jdGlvbih0aGlzLCBcIkNUQUdlbmVyYXRvclwiLCB7XG4gICAgICBydW50aW1lOiBsYW1iZGEuUnVudGltZS5OT0RFSlNfMjJfWCxcbiAgICAgIGVudHJ5OiBcImxhbWJkYS9jdGFfdG9rZW5fZ2VuZXJhdG9yLmpzXCIsXG4gICAgICBoYW5kbGVyOiBcImhhbmRsZXJcIixcbiAgICAgIHRpbWVvdXQ6IER1cmF0aW9uLnNlY29uZHMoMTApLFxuICAgICAgZW52aXJvbm1lbnQ6IHsgU0VDUkVUX05BTUU6IHNpZ25pbmdTZWNyZXQuc2VjcmV0TmFtZSB9LFxuICAgIH0pO1xuXG4gICAgLy8gVG9rZW4gZ2VuZXJhdG9yIChQeXRob24gU0RLKVxuICAgIGNvbnN0IGdlbmVyYXRvclB5dGhvbiA9IG5ldyBsYW1iZGEuRnVuY3Rpb24odGhpcywgXCJDVEFHZW5lcmF0b3JQeXRob25cIiwge1xuICAgICAgcnVudGltZTogbGFtYmRhLlJ1bnRpbWUuUFlUSE9OXzNfMTMsXG4gICAgICBoYW5kbGVyOiBcImhhbmRsZXIuaGFuZGxlclwiLFxuICAgICAgY29kZTogbGFtYmRhLkNvZGUuZnJvbUFzc2V0KFwibGFtYmRhLXB5dGhvblwiKSxcbiAgICAgIHRpbWVvdXQ6IER1cmF0aW9uLnNlY29uZHMoMTApLFxuICAgICAgZW52aXJvbm1lbnQ6IHsgU0VDUkVUX05BTUU6IHNpZ25pbmdTZWNyZXQuc2VjcmV0TmFtZSB9LFxuICAgIH0pO1xuXG4gICAgLy8gVG9rZW4gZ2VuZXJhdG9yIChSdWJ5IFNESylcbiAgICBjb25zdCBnZW5lcmF0b3JSdWJ5ID0gbmV3IGxhbWJkYS5GdW5jdGlvbih0aGlzLCBcIkNUQUdlbmVyYXRvclJ1YnlcIiwge1xuICAgICAgcnVudGltZTogbGFtYmRhLlJ1bnRpbWUuUlVCWV8zXzQsXG4gICAgICBoYW5kbGVyOiBcImhhbmRsZXIuaGFuZGxlclwiLFxuICAgICAgY29kZTogbGFtYmRhLkNvZGUuZnJvbUFzc2V0KFwibGFtYmRhLXJ1YnlcIiksXG4gICAgICB0aW1lb3V0OiBEdXJhdGlvbi5zZWNvbmRzKDEwKSxcbiAgICAgIGVudmlyb25tZW50OiB7IFNFQ1JFVF9OQU1FOiBzaWduaW5nU2VjcmV0LnNlY3JldE5hbWUgfSxcbiAgICB9KTtcblxuICAgIC8vIFRva2VuIHJldm9jYXRpb24gaGFuZGxlclxuICAgIGNvbnN0IHJldm9rZXIgPSBuZXcgbGFtYmRhLkZ1bmN0aW9uKHRoaXMsIFwiQ1RBUmV2b2tlclwiLCB7XG4gICAgICBydW50aW1lOiBsYW1iZGEuUnVudGltZS5OT0RFSlNfMjJfWCxcbiAgICAgIGhhbmRsZXI6IFwiY3RhX3Jldm9jYXRpb24uaGFuZGxlclwiLFxuICAgICAgY29kZTogbGFtYmRhLkNvZGUuZnJvbUFzc2V0KFwibGFtYmRhXCIpLFxuICAgICAgdGltZW91dDogRHVyYXRpb24uc2Vjb25kcygxMCksXG4gICAgICBlbnZpcm9ubWVudDogeyBLVlNfQVJOOiB0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUFybiB9LFxuICAgIH0pO1xuXG4gICAgc2lnbmluZ1NlY3JldC5ncmFudFJlYWQoZ2VuZXJhdG9yKTtcbiAgICBzaWduaW5nU2VjcmV0LmdyYW50UmVhZChnZW5lcmF0b3JQeXRob24pO1xuICAgIHNpZ25pbmdTZWNyZXQuZ3JhbnRSZWFkKGdlbmVyYXRvclJ1YnkpO1xuXG4gICAgLy8gR3JhbnQgS1ZTIHVwZGF0ZSBwZXJtaXNzaW9uIHZpYSBJQU0gcG9saWN5XG4gICAgcmV2b2tlci5hZGRUb1JvbGVQb2xpY3kobmV3IGlhbS5Qb2xpY3lTdGF0ZW1lbnQoe1xuICAgICAgZWZmZWN0OiBpYW0uRWZmZWN0LkFMTE9XLFxuICAgICAgYWN0aW9uczogW1wiY2xvdWRmcm9udC1rZXl2YWx1ZXN0b3JlOlB1dEtleVwiLCBcImNsb3VkZnJvbnQta2V5dmFsdWVzdG9yZTpEZXNjcmliZUtleVZhbHVlU3RvcmVcIl0sXG4gICAgICByZXNvdXJjZXM6IFt0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUFybl0sXG4gICAgfSkpO1xuXG4gICAgLy8gLS0tIEtleSBzeW5jIExhbWJkYSAoY3VzdG9tIHJlc291cmNlICsgcm90YXRpb24pIC0tLVxuICAgIGNvbnN0IHJvdGF0aW9uT3ZlcmxhcCA9IE51bWJlcihjb25maWcubWFpbi5yb3RhdGlvbk92ZXJsYXBTZWNvbmRzID8/IDcyMDApO1xuICAgIGNvbnN0IHJvdGF0aW9uUHJvcGFnYXRpb24gPSBOdW1iZXIoY29uZmlnLm1haW4ucm90YXRpb25Qcm9wYWdhdGlvblNlY29uZHMgPz8gMzAwKTtcbiAgICBpZiAoIU51bWJlci5pc1NhZmVJbnRlZ2VyKHJvdGF0aW9uT3ZlcmxhcCkgfHwgcm90YXRpb25PdmVybGFwIDwgNzIwMCB8fFxuICAgICAgICAhTnVtYmVyLmlzU2FmZUludGVnZXIocm90YXRpb25Qcm9wYWdhdGlvbikgfHwgcm90YXRpb25Qcm9wYWdhdGlvbiA8IDMwMCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwiUm90YXRpb24gcmVxdWlyZXMgaW50ZWdlciBvdmVybGFwID49NzIwMHMgYW5kIHByb3BhZ2F0aW9uID49MzAwc1wiKTtcbiAgICB9XG4gICAgaWYgKHJvdGF0aW9uUHJvcGFnYXRpb24gKyByb3RhdGlvbk92ZXJsYXAgKyA2MCArIDYwID4gMzE0NDk2MDApIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIlJvdGF0aW9uIHByb3BhZ2F0aW9uICsgb3ZlcmxhcCArIDYwcyBtaW50IGNhY2hlICsgNjBzIGluLWZsaWdodCBhbGxvd2FuY2UgbXVzdCBub3QgZXhjZWVkIDMxNDQ5NjAwcyAoMzY0IGRheXMpLCByZXNlcnZpbmcgb25lIGRheSBmb3Igd29ya2Zsb3cgdGFza3MgYW5kIHJldHJpZXNcIik7XG4gICAgfVxuICAgIGNvbnN0IHN5bmNLZXlzVG9LdnMgPSBuZXcgbGFtYmRhLkZ1bmN0aW9uKHRoaXMsIFwiU3luY0tleXNUb0t2c1wiLCB7XG4gICAgICBydW50aW1lOiBsYW1iZGEuUnVudGltZS5OT0RFSlNfMjJfWCxcbiAgICAgIGhhbmRsZXI6IFwiaW5kZXguaGFuZGxlclwiLFxuICAgICAgY29kZTogbGFtYmRhLkNvZGUuZnJvbUFzc2V0KFwibGFtYmRhL3N5bmNfa2V5c1wiKSxcbiAgICAgIHRpbWVvdXQ6IER1cmF0aW9uLnNlY29uZHMoMzApLFxuICAgICAgZW52aXJvbm1lbnQ6IHtcbiAgICAgICAgU0VDUkVUX05BTUU6IHNpZ25pbmdTZWNyZXQuc2VjcmV0TmFtZSxcbiAgICAgICAgS1ZTX0FSTjogdGhpcy5rdlN0b3JlLmtleVZhbHVlU3RvcmVBcm4sXG4gICAgICAgIFJPVEFUSU9OX09WRVJMQVBfU0VDT05EUzogU3RyaW5nKHJvdGF0aW9uT3ZlcmxhcCksXG4gICAgICAgIFJPVEFUSU9OX1BST1BBR0FUSU9OX1NFQ09ORFM6IFN0cmluZyhyb3RhdGlvblByb3BhZ2F0aW9uKSxcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICBzaWduaW5nU2VjcmV0LmdyYW50UmVhZChzeW5jS2V5c1RvS3ZzKTtcbiAgICBzaWduaW5nU2VjcmV0LmdyYW50V3JpdGUoc3luY0tleXNUb0t2cyk7XG4gICAgc3luY0tleXNUb0t2cy5hZGRUb1JvbGVQb2xpY3kobmV3IGlhbS5Qb2xpY3lTdGF0ZW1lbnQoe1xuICAgICAgZWZmZWN0OiBpYW0uRWZmZWN0LkFMTE9XLFxuICAgICAgYWN0aW9uczogW1xuICAgICAgICBcImNsb3VkZnJvbnQta2V5dmFsdWVzdG9yZTpHZXRLZXlcIixcbiAgICAgICAgXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6VXBkYXRlS2V5c1wiLFxuICAgICAgICBcImNsb3VkZnJvbnQta2V5dmFsdWVzdG9yZTpEZXNjcmliZUtleVZhbHVlU3RvcmVcIixcbiAgICAgIF0sXG4gICAgICByZXNvdXJjZXM6IFt0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUFybl0sXG4gICAgfSkpO1xuXG4gICAgLy8gQ3VzdG9tIHJlc291cmNlOiBzeW5jIGtleSB0byBLVlMgb24gZGVwbG95XG4gICAgY29uc3Qga2V5U3luY1Byb3ZpZGVyID0gbmV3IGN1c3RvbV9yZXNvdXJjZXMuUHJvdmlkZXIodGhpcywgXCJLZXlTeW5jUHJvdmlkZXJcIiwge1xuICAgICAgb25FdmVudEhhbmRsZXI6IHN5bmNLZXlzVG9LdnMsXG4gICAgfSk7XG5cbiAgICBuZXcgQ3VzdG9tUmVzb3VyY2UodGhpcywgXCJLZXlTeW5jUmVzb3VyY2VcIiwge1xuICAgICAgc2VydmljZVRva2VuOiBrZXlTeW5jUHJvdmlkZXIuc2VydmljZVRva2VuLFxuICAgICAgcHJvcGVydGllczoge1xuICAgICAgICAvLyBGb3JjZSB1cGRhdGUgb24gZWFjaCBkZXBsb3kgdG8gZW5zdXJlIGtleSBpcyBzeW5jZWRcbiAgICAgICAgVGltZXN0YW1wOiBEYXRlLm5vdygpLnRvU3RyaW5nKCksXG4gICAgICB9LFxuICAgIH0pO1xuXG4gICAgLy8gRHVyYWJsZSwgZXhlY3V0aW9uLW93bmVkIHJvdGF0aW9uLiBPbmx5IG1ldGFkYXRhIGVudGVycyB3b3JrZmxvdyBoaXN0b3J5LlxuICAgIGNvbnN0IHJvdGF0aW9uVGFzayA9IChpZDogc3RyaW5nLCBhY3Rpb246IHN0cmluZykgPT4ge1xuICAgICAgY29uc3QgdGFzayA9IG5ldyB0YXNrcy5MYW1iZGFJbnZva2UodGhpcywgaWQsIHtcbiAgICAgICAgbGFtYmRhRnVuY3Rpb246IHN5bmNLZXlzVG9LdnMsXG4gICAgICAgIHBheWxvYWQ6IHNmbi5UYXNrSW5wdXQuZnJvbU9iamVjdCh7XG4gICAgICAgICAgYWN0aW9uLFxuICAgICAgICAgIGV4ZWN1dGlvbklkOiBzZm4uSnNvblBhdGguc3RyaW5nQXQoXCIkJC5FeGVjdXRpb24uSWRcIiksXG4gICAgICAgIH0pLFxuICAgICAgICByZXN1bHRQYXRoOiBcIiQucm90YXRpb25cIixcbiAgICAgIH0pO1xuICAgICAgdGFzay5hZGRSZXRyeSh7IGVycm9yczogW1wiU3RhdGVzLlRhc2tGYWlsZWRcIl0sIGludGVydmFsOiBEdXJhdGlvbi5zZWNvbmRzKDIpLCBtYXhBdHRlbXB0czogNiwgYmFja29mZlJhdGU6IDIgfSk7XG4gICAgICByZXR1cm4gdGFzaztcbiAgICB9O1xuICAgIGNvbnN0IHByZXBhcmVLZXkgPSByb3RhdGlvblRhc2soXCJQcmVwYXJlU2lnbmluZ0tleVwiLCBcInByZXBhcmVcIik7XG4gICAgY29uc3Qgd2FpdEZvckVkZ2UgPSBuZXcgc2ZuLldhaXQodGhpcywgXCJXYWl0Rm9yRWRnZVByb3BhZ2F0aW9uXCIsIHtcbiAgICAgIHRpbWU6IHNmbi5XYWl0VGltZS50aW1lc3RhbXBQYXRoKFwiJC5yb3RhdGlvbi5QYXlsb2FkLnByb3BhZ2F0aW9uUmVhZHlUaW1lc3RhbXBcIiksXG4gICAgfSk7XG4gICAgY29uc3QgcHJvbW90ZUtleSA9IHJvdGF0aW9uVGFzayhcIlByb21vdGVNaW50S2V5XCIsIFwicHJvbW90ZVwiKTtcbiAgICBjb25zdCBmaW5hbGl6ZU92ZXJsYXAgPSByb3RhdGlvblRhc2soXCJGaW5hbGl6ZU92ZXJsYXBcIiwgXCJmaW5hbGl6ZVwiKTtcbiAgICBjb25zdCB3YWl0Rm9yT3ZlcmxhcCA9IG5ldyBzZm4uV2FpdCh0aGlzLCBcIldhaXRGb3JPdmVybGFwXCIsIHtcbiAgICAgIHRpbWU6IHNmbi5XYWl0VGltZS50aW1lc3RhbXBQYXRoKFwiJC5yb3RhdGlvbi5QYXlsb2FkLmNsZWFudXBUaW1lc3RhbXBcIiksXG4gICAgfSk7XG4gICAgY29uc3QgY2xlYW51cEtleSA9IHJvdGF0aW9uVGFzayhcIlJlbW92ZVByZXZpb3VzS2V5XCIsIFwiY2xlYW51cFwiKTtcbiAgICBjb25zdCByb3RhdGlvbldvcmtmbG93ID0gbmV3IHNmbi5TdGF0ZU1hY2hpbmUodGhpcywgXCJLZXlSb3RhdGlvbldvcmtmbG93XCIsIHtcbiAgICAgIHN0YXRlTWFjaGluZU5hbWU6IGAke0F3cy5TVEFDS19OQU1FfV9Sb3RhdGVLZXlzYCxcbiAgICAgIGRlZmluaXRpb25Cb2R5OiBzZm4uRGVmaW5pdGlvbkJvZHkuZnJvbUNoYWluYWJsZShcbiAgICAgICAgcHJlcGFyZUtleS5uZXh0KHdhaXRGb3JFZGdlKS5uZXh0KHByb21vdGVLZXkpLm5leHQoZmluYWxpemVPdmVybGFwKS5uZXh0KHdhaXRGb3JPdmVybGFwKS5uZXh0KGNsZWFudXBLZXkpXG4gICAgICApLFxuICAgIH0pO1xuXG4gICAgLy8gS2VlcCBkaXNhYmxlZCB1bnRpbCB0aGUgdXBkYXRlZCB2YWxpZGF0b3JzIGFuZCBtaW50cyBhcmUgdmVyaWZpZWQuXG4gICAgY29uc3Qgcm90YXRpb25TY2hlZHVsZSA9IGNvbmZpZy5tYWluLnJvdGF0aW9uRnJlcXVlbmN5IHx8IFwiMzBkXCI7XG4gICAgY29uc3Qgcm90YXRpb25SYXRlID0gdGhpcy5wYXJzZVJvdGF0aW9uUmF0ZShyb3RhdGlvblNjaGVkdWxlKTtcbiAgICBuZXcgZXZlbnRzLlJ1bGUodGhpcywgXCJLZXlSb3RhdGlvblNjaGVkdWxlXCIsIHtcbiAgICAgIHNjaGVkdWxlOiBldmVudHMuU2NoZWR1bGUucmF0ZShyb3RhdGlvblJhdGUpLFxuICAgICAgZW5hYmxlZDogY29uZmlnLm1haW4ucm90YXRpb25FbmFibGVkID09PSB0cnVlLFxuICAgICAgdGFyZ2V0czogW25ldyB0YXJnZXRzLlNmblN0YXRlTWFjaGluZShyb3RhdGlvbldvcmtmbG93KV0sXG4gICAgfSk7XG5cbiAgICAvLyBBUEkgR2F0ZXdheVxuICAgIGNvbnN0IGFwaSA9IG5ldyBhcGlnYXRld2F5LlJlc3RBcGkodGhpcywgXCJDVEFBUElcIiwge1xuICAgICAgcmVzdEFwaU5hbWU6IFwiQ1RBIFRva2VuIEFQSVwiLFxuICAgICAgZGVmYXVsdENvcnNQcmVmbGlnaHRPcHRpb25zOiB7XG4gICAgICAgIGFsbG93T3JpZ2luczogYXBpZ2F0ZXdheS5Db3JzLkFMTF9PUklHSU5TLFxuICAgICAgICBhbGxvd01ldGhvZHM6IGFwaWdhdGV3YXkuQ29ycy5BTExfTUVUSE9EUyxcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICAvLyBBdHRhY2ggQ09SUyBoZWFkZXJzIHRvIEFQSSBHYXRld2F5J3MgZGVmYXVsdCBnYXRld2F5IHJlc3BvbnNlcyBzbyB0aGF0XG4gICAgLy8gaW50ZWdyYXRpb24gZXJyb3JzIChlLmcuIGEgTGFtYmRhIDV4eC90aW1lb3V0LCBvciBhIDR4eCkgc3RpbGwgY2FycnlcbiAgICAvLyBBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4uIFdpdGhvdXQgdGhpcywgYW4gZXJyb3JlZCByZXF1ZXN0IHJldHVybnMgYVxuICAgIC8vIHJlc3BvbnNlIHdpdGggbm8gQ09SUyBoZWFkZXIsIHdoaWNoIGJyb3dzZXJzIHN1cmZhY2UgYXMgYSBtaXNsZWFkaW5nXG4gICAgLy8gXCJibG9ja2VkIGJ5IENPUlMgcG9saWN5XCIgZXJyb3IgdGhhdCBtYXNrcyB0aGUgcmVhbCBzdGF0dXMgY29kZS5cbiAgICBjb25zdCBjb3JzUmVzcG9uc2VIZWFkZXJzID0ge1xuICAgICAgXCJBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW5cIjogXCInKidcIixcbiAgICAgIFwiQWNjZXNzLUNvbnRyb2wtQWxsb3ctSGVhZGVyc1wiOiBcIicqJ1wiLFxuICAgIH07XG4gICAgYXBpLmFkZEdhdGV3YXlSZXNwb25zZShcIkRlZmF1bHQ0WFhcIiwge1xuICAgICAgdHlwZTogYXBpZ2F0ZXdheS5SZXNwb25zZVR5cGUuREVGQVVMVF80WFgsXG4gICAgICByZXNwb25zZUhlYWRlcnM6IGNvcnNSZXNwb25zZUhlYWRlcnMsXG4gICAgfSk7XG4gICAgYXBpLmFkZEdhdGV3YXlSZXNwb25zZShcIkRlZmF1bHQ1WFhcIiwge1xuICAgICAgdHlwZTogYXBpZ2F0ZXdheS5SZXNwb25zZVR5cGUuREVGQVVMVF81WFgsXG4gICAgICByZXNwb25zZUhlYWRlcnM6IGNvcnNSZXNwb25zZUhlYWRlcnMsXG4gICAgfSk7XG5cbiAgICBjb25zdCB0b2tlblJlc291cmNlID0gYXBpLnJvb3QuYWRkUmVzb3VyY2UoXCJ0b2tlblwiKTtcbiAgICB0b2tlblJlc291cmNlLmFkZE1ldGhvZChcIlBPU1RcIiwgbmV3IGFwaWdhdGV3YXkuTGFtYmRhSW50ZWdyYXRpb24oZ2VuZXJhdG9yKSk7XG5cbiAgICBjb25zdCB0b2tlblB5dGhvblJlc291cmNlID0gYXBpLnJvb3QuYWRkUmVzb3VyY2UoXCJ0b2tlbi1weXRob25cIik7XG4gICAgdG9rZW5QeXRob25SZXNvdXJjZS5hZGRNZXRob2QoXCJQT1NUXCIsIG5ldyBhcGlnYXRld2F5LkxhbWJkYUludGVncmF0aW9uKGdlbmVyYXRvclB5dGhvbikpO1xuXG4gICAgY29uc3QgdG9rZW5SdWJ5UmVzb3VyY2UgPSBhcGkucm9vdC5hZGRSZXNvdXJjZShcInRva2VuLXJ1YnlcIik7XG4gICAgdG9rZW5SdWJ5UmVzb3VyY2UuYWRkTWV0aG9kKFwiUE9TVFwiLCBuZXcgYXBpZ2F0ZXdheS5MYW1iZGFJbnRlZ3JhdGlvbihnZW5lcmF0b3JSdWJ5KSk7XG4gICAgXG4gICAgY29uc3QgcmV2b2tlUmVzb3VyY2UgPSBhcGkucm9vdC5hZGRSZXNvdXJjZShcInJldm9rZVwiKTtcbiAgICByZXZva2VSZXNvdXJjZS5hZGRNZXRob2QoXCJQT1NUXCIsIG5ldyBhcGlnYXRld2F5LkxhbWJkYUludGVncmF0aW9uKHJldm9rZXIpKTtcblxuICAgIC8vIFdBRnYyIFdlYiBBQ0wg4oCUIHJhdGUtbGltaXQgUE9TVCAvYXBpL3Rva2VuIHBlciBzb3VyY2UgSVAuXG4gICAgLy86IGF1dG9tYXRlZC1zY3JhcGluZyBtaXRpZ2F0aW9uLiBSYXRlLWJhc2VkIHJ1bGVzIHVzZSBhXG4gICAgLy8gcm9sbGluZyA1LW1pbnV0ZSB3aW5kb3c7IDMwMCByZXEvNW1pbiDiiYggNjAgcmVxL21pbiBwZXIgSVAsIHdlbGxcbiAgICAvLyBhYm92ZSBsZWdpdGltYXRlIHBsYXllciB0cmFmZmljIChtaW50IG9uY2Ug4oaSIDJoIFRUTCDihpIgbmV4dCBtaW50KVxuICAgIC8vIGJ1dCB0aWdodCBlbm91Z2ggdG8gc3RvcCBhIG1pbnQteW91ci1vd24tdG9rZW4gc2NyYXBlci5cbiAgICAvLyBCbG9ja2VkIHJlcXVlc3RzIGdldCBhIGN1c3RvbSA0MjkgcmVzcG9uc2UgaW5zdGVhZCBvZiB0aGUgZGVmYXVsdCA0MDMuXG4gICAgY29uc3QgcmF0ZUxpbWl0Qm9keSA9IFwiQ1RBV2ViQWNsUmF0ZUxpbWl0NDI5XCI7XG4gICAgY29uc3Qgd2ViQWNsID0gbmV3IHdhZnYyLkNmbldlYkFDTCh0aGlzLCBcIkNUQVdlYkFjbFwiLCB7XG4gICAgICBuYW1lOiBgJHtBd3MuU1RBQ0tfTkFNRX0tdG9rZW4tcmF0ZS1saW1pdGAsXG4gICAgICBkZXNjcmlwdGlvbjogXCJSYXRlLWxpbWl0IFBPU1QgL2FwaS90b2tlbiB0byBtaXRpZ2F0ZSBhdXRvbWF0ZWQgQ1dUIG1pbnRpbmdcIixcbiAgICAgIHNjb3BlOiBcIkNMT1VERlJPTlRcIixcbiAgICAgIGRlZmF1bHRBY3Rpb246IHsgYWxsb3c6IHt9IH0sXG4gICAgICB2aXNpYmlsaXR5Q29uZmlnOiB7XG4gICAgICAgIGNsb3VkV2F0Y2hNZXRyaWNzRW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgbWV0cmljTmFtZTogYCR7QXdzLlNUQUNLX05BTUV9LXdlYi1hY2xgLFxuICAgICAgICBzYW1wbGVkUmVxdWVzdHNFbmFibGVkOiB0cnVlLFxuICAgICAgfSxcbiAgICAgIGN1c3RvbVJlc3BvbnNlQm9kaWVzOiB7XG4gICAgICAgIFtyYXRlTGltaXRCb2R5XToge1xuICAgICAgICAgIGNvbnRlbnRUeXBlOiBcIkFQUExJQ0FUSU9OX0pTT05cIixcbiAgICAgICAgICBjb250ZW50OiBKU09OLnN0cmluZ2lmeSh7IGVycm9yOiBcInJhdGVfbGltaXRlZFwiLCBtZXNzYWdlOiBcIlRvbyBtYW55IHRva2VuIG1pbnQgcmVxdWVzdHMgZnJvbSB0aGlzIElQOyB0cnkgYWdhaW4gaW4gYSBmZXcgbWludXRlcy5cIiB9KSxcbiAgICAgICAgfSxcbiAgICAgIH0sXG4gICAgICBydWxlczogW3tcbiAgICAgICAgbmFtZTogXCJUb2tlbk1pbnRSYXRlTGltaXRcIixcbiAgICAgICAgcHJpb3JpdHk6IDAsXG4gICAgICAgIGFjdGlvbjoge1xuICAgICAgICAgIGJsb2NrOiB7XG4gICAgICAgICAgICBjdXN0b21SZXNwb25zZToge1xuICAgICAgICAgICAgICByZXNwb25zZUNvZGU6IDQyOSxcbiAgICAgICAgICAgICAgY3VzdG9tUmVzcG9uc2VCb2R5S2V5OiByYXRlTGltaXRCb2R5LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBzdGF0ZW1lbnQ6IHtcbiAgICAgICAgICByYXRlQmFzZWRTdGF0ZW1lbnQ6IHtcbiAgICAgICAgICAgIGxpbWl0OiAzMDAsXG4gICAgICAgICAgICBhZ2dyZWdhdGVLZXlUeXBlOiBcIklQXCIsXG4gICAgICAgICAgICBzY29wZURvd25TdGF0ZW1lbnQ6IHtcbiAgICAgICAgICAgICAgYnl0ZU1hdGNoU3RhdGVtZW50OiB7XG4gICAgICAgICAgICAgICAgZmllbGRUb01hdGNoOiB7IHVyaVBhdGg6IHt9IH0sXG4gICAgICAgICAgICAgICAgcG9zaXRpb25hbENvbnN0cmFpbnQ6IFwiU1RBUlRTX1dJVEhcIixcbiAgICAgICAgICAgICAgICBzZWFyY2hTdHJpbmc6IFwiL2FwaS90b2tlblwiLFxuICAgICAgICAgICAgICAgIHRleHRUcmFuc2Zvcm1hdGlvbnM6IFt7IHByaW9yaXR5OiAwLCB0eXBlOiBcIk5PTkVcIiB9XSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgdmlzaWJpbGl0eUNvbmZpZzoge1xuICAgICAgICAgIGNsb3VkV2F0Y2hNZXRyaWNzRW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICBtZXRyaWNOYW1lOiBgJHtBd3MuU1RBQ0tfTkFNRX0tdG9rZW4tcmF0ZS1saW1pdGAsXG4gICAgICAgICAgc2FtcGxlZFJlcXVlc3RzRW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgfSxcbiAgICAgIH1dLFxuICAgIH0pO1xuXG4gICAgLy8gRGVtbyB3ZWJzaXRlIChjb25kaXRpb25hbClcbiAgICBsZXQgZGlzdHJpYnV0aW9uOiBjbG91ZGZyb250LkRpc3RyaWJ1dGlvbjtcbiAgICBsZXQgZGVtb0J1Y2tldDogczMuQnVja2V0IHwgdW5kZWZpbmVkO1xuXG4gICAgaWYgKGNvbmZpZy5tYWluLmVuYWJsZURlbW8pIHtcbiAgICAgIGRlbW9CdWNrZXQgPSBuZXcgczMuQnVja2V0KHRoaXMsIFwiRGVtb1dlYnNpdGVcIiwge1xuICAgICAgICByZW1vdmFsUG9saWN5OiBSZW1vdmFsUG9saWN5LkRFU1RST1ksXG4gICAgICAgIGF1dG9EZWxldGVPYmplY3RzOiB0cnVlLFxuICAgICAgfSk7XG5cbiAgICAgIG5ldyBzM2RlcGxveS5CdWNrZXREZXBsb3ltZW50KHRoaXMsIFwiRGVwbG95RGVtb1NpdGVcIiwge1xuICAgICAgICBzb3VyY2VzOiBbczNkZXBsb3kuU291cmNlLmFzc2V0KFwicmVzb3VyY2VzL2RlbW8td2Vic2l0ZVwiKV0sXG4gICAgICAgIGRlc3RpbmF0aW9uQnVja2V0OiBkZW1vQnVja2V0LFxuICAgICAgICBkZXN0aW5hdGlvbktleVByZWZpeDogXCJ3ZWJzaXRlXCIsXG4gICAgICAgIHBydW5lOiBmYWxzZSxcbiAgICAgIH0pO1xuXG4gICAgICBkaXN0cmlidXRpb24gPSBuZXcgY2xvdWRmcm9udC5EaXN0cmlidXRpb24odGhpcywgXCJDVEFEaXN0cmlidXRpb25cIiwge1xuICAgICAgICB3ZWJBY2xJZDogd2ViQWNsLmF0dHJBcm4sXG4gICAgICAgIGRlZmF1bHRCZWhhdmlvcjoge1xuICAgICAgICAgIG9yaWdpbjogbmV3IEh0dHBPcmlnaW4oXCJjZG4ubWVkaWFwbGF5cGVuLmNvbVwiKSxcbiAgICAgICAgICB2aWV3ZXJQcm90b2NvbFBvbGljeTogY2xvdWRmcm9udC5WaWV3ZXJQcm90b2NvbFBvbGljeS5SRURJUkVDVF9UT19IVFRQUyxcbiAgICAgICAgICBjYWNoZVBvbGljeTogbmV3IGNsb3VkZnJvbnQuQ2FjaGVQb2xpY3kodGhpcywgXCJDVEFDYWNoZVBvbGljeVwiLCB7XG4gICAgICAgICAgICBoZWFkZXJCZWhhdmlvcjogY2xvdWRmcm9udC5DYWNoZUhlYWRlckJlaGF2aW9yLmFsbG93TGlzdChcbiAgICAgICAgICAgICAgXCJDbG91ZEZyb250LVZpZXdlci1Db3VudHJ5XCJcbiAgICAgICAgICAgICksXG4gICAgICAgICAgfSksXG4gICAgICAgICAgcmVzcG9uc2VIZWFkZXJzUG9saWN5OiBuZXcgY2xvdWRmcm9udC5SZXNwb25zZUhlYWRlcnNQb2xpY3kodGhpcywgXCJDVEFDb3JzUmVzcG9uc2VQb2xpY3lcIiwge1xuICAgICAgICAgICAgcmVzcG9uc2VIZWFkZXJzUG9saWN5TmFtZTogYCR7QXdzLlNUQUNLX05BTUV9LUNUQS1DT1JTYCxcbiAgICAgICAgICAgIGNvcnNCZWhhdmlvcjoge1xuICAgICAgICAgICAgICBhY2Nlc3NDb250cm9sQWxsb3dPcmlnaW5zOiBbXCIqXCJdLFxuICAgICAgICAgICAgICBhY2Nlc3NDb250cm9sQWxsb3dIZWFkZXJzOiBbXCJDVEEtQ29tbW9uLUFjY2Vzcy1Ub2tlblwiLCBcIkNvbnRlbnQtVHlwZVwiXSxcbiAgICAgICAgICAgICAgYWNjZXNzQ29udHJvbEFsbG93TWV0aG9kczogW1wiR0VUXCIsIFwiSEVBRFwiLCBcIk9QVElPTlNcIl0sXG4gICAgICAgICAgICAgIGFjY2Vzc0NvbnRyb2xFeHBvc2VIZWFkZXJzOiBbXCJDVEEtQ29tbW9uLUFjY2Vzcy1Ub2tlblwiXSxcbiAgICAgICAgICAgICAgYWNjZXNzQ29udHJvbEFsbG93Q3JlZGVudGlhbHM6IGZhbHNlLFxuICAgICAgICAgICAgICBhY2Nlc3NDb250cm9sTWF4QWdlOiBEdXJhdGlvbi5ob3VycygyNCksXG4gICAgICAgICAgICAgIG9yaWdpbk92ZXJyaWRlOiB0cnVlLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9KSxcbiAgICAgICAgICBvcmlnaW5SZXF1ZXN0UG9saWN5OiBjbG91ZGZyb250Lk9yaWdpblJlcXVlc3RQb2xpY3kuQUxMX1ZJRVdFUl9FWENFUFRfSE9TVF9IRUFERVIsXG4gICAgICAgICAgZnVuY3Rpb25Bc3NvY2lhdGlvbnM6IFt7XG4gICAgICAgICAgICBmdW5jdGlvbjogdmFsaWRhdG9yLFxuICAgICAgICAgICAgZXZlbnRUeXBlOiBjbG91ZGZyb250LkZ1bmN0aW9uRXZlbnRUeXBlLlZJRVdFUl9SRVFVRVNULFxuICAgICAgICAgIH1dLFxuICAgICAgICB9LFxuICAgICAgICBhZGRpdGlvbmFsQmVoYXZpb3JzOiB7XG4gICAgICAgICAgXCIvYXBpLypcIjoge1xuICAgICAgICAgICAgb3JpZ2luOiBuZXcgUmVzdEFwaU9yaWdpbihhcGkpLFxuICAgICAgICAgICAgdmlld2VyUHJvdG9jb2xQb2xpY3k6IGNsb3VkZnJvbnQuVmlld2VyUHJvdG9jb2xQb2xpY3kuUkVESVJFQ1RfVE9fSFRUUFMsXG4gICAgICAgICAgICBhbGxvd2VkTWV0aG9kczogY2xvdWRmcm9udC5BbGxvd2VkTWV0aG9kcy5BTExPV19BTEwsXG4gICAgICAgICAgICBjYWNoZVBvbGljeTogY2xvdWRmcm9udC5DYWNoZVBvbGljeS5DQUNISU5HX0RJU0FCTEVELFxuICAgICAgICAgICAgb3JpZ2luUmVxdWVzdFBvbGljeTogY2xvdWRmcm9udC5PcmlnaW5SZXF1ZXN0UG9saWN5LkFMTF9WSUVXRVJfRVhDRVBUX0hPU1RfSEVBREVSLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCIvd2Vic2l0ZS8qXCI6IHtcbiAgICAgICAgICAgIG9yaWdpbjogUzNCdWNrZXRPcmlnaW4ud2l0aE9yaWdpbkFjY2Vzc0NvbnRyb2woZGVtb0J1Y2tldCksXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuXG4gICAgfSBlbHNlIHtcbiAgICAgIGRpc3RyaWJ1dGlvbiA9IG5ldyBjbG91ZGZyb250LkRpc3RyaWJ1dGlvbih0aGlzLCBcIkNUQURpc3RyaWJ1dGlvblwiLCB7XG4gICAgICAgIHdlYkFjbElkOiB3ZWJBY2wuYXR0ckFybixcbiAgICAgICAgZGVmYXVsdEJlaGF2aW9yOiB7XG4gICAgICAgICAgb3JpZ2luOiBuZXcgUmVzdEFwaU9yaWdpbihhcGkpLFxuICAgICAgICAgIGZ1bmN0aW9uQXNzb2NpYXRpb25zOiBbe1xuICAgICAgICAgICAgZnVuY3Rpb246IHZhbGlkYXRvcixcbiAgICAgICAgICAgIGV2ZW50VHlwZTogY2xvdWRmcm9udC5GdW5jdGlvbkV2ZW50VHlwZS5WSUVXRVJfUkVRVUVTVCxcbiAgICAgICAgICB9XSxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHRoaXMuZGlzdHJpYnV0aW9uID0gZGlzdHJpYnV0aW9uO1xuICAgIGlmIChjb25maWcubWFpbi5lbmFibGVEZW1vKSB7XG4gICAgICB0aGlzLmRlbW9CdWNrZXQgPSBkZW1vQnVja2V0ITtcbiAgICB9XG5cbiAgICAvLyAtLS0gUmVhbC1UaW1lIExvZ2dpbmcgdmlhIEtpbmVzaXMgLS0tXG4gICAgY29uc3QgbG9nU3RyZWFtID0gbmV3IGtpbmVzaXMuU3RyZWFtKHRoaXMsIFwiUmVhbHRpbWVMb2dTdHJlYW1cIiwge1xuICAgICAgc3RyZWFtTW9kZToga2luZXNpcy5TdHJlYW1Nb2RlLk9OX0RFTUFORCxcbiAgICAgIHJldGVudGlvblBlcmlvZDogRHVyYXRpb24uaG91cnMoMjQpLFxuICAgIH0pO1xuICAgIHRoaXMubG9nU3RyZWFtID0gbG9nU3RyZWFtO1xuXG4gICAgY29uc3QgY2ZLaW5lc2lzUm9sZSA9IG5ldyBpYW0uUm9sZSh0aGlzLCBcIkNsb3VkRnJvbnRLaW5lc2lzUm9sZVwiLCB7XG4gICAgICBhc3N1bWVkQnk6IG5ldyBpYW0uU2VydmljZVByaW5jaXBhbChcImNsb3VkZnJvbnQuYW1hem9uYXdzLmNvbVwiKSxcbiAgICB9KTtcbiAgICBsb2dTdHJlYW0uZ3JhbnRXcml0ZShjZktpbmVzaXNSb2xlKTtcblxuICAgIGNvbnN0IHJlYWx0aW1lTG9nQ29uZmlnID0gbmV3IGNsb3VkZnJvbnQuQ2ZuUmVhbHRpbWVMb2dDb25maWcodGhpcywgXCJSZWFsdGltZUxvZ0NvbmZpZ1wiLCB7XG4gICAgICBuYW1lOiBgJHtBd3MuU1RBQ0tfTkFNRX0tcmVhbHRpbWUtbG9nc2AsXG4gICAgICBzYW1wbGluZ1JhdGU6IDEwMCxcbiAgICAgIGVuZFBvaW50czogW3tcbiAgICAgICAgc3RyZWFtVHlwZTogXCJLaW5lc2lzXCIsXG4gICAgICAgIGtpbmVzaXNTdHJlYW1Db25maWc6IHtcbiAgICAgICAgICByb2xlQXJuOiBjZktpbmVzaXNSb2xlLnJvbGVBcm4sXG4gICAgICAgICAgc3RyZWFtQXJuOiBsb2dTdHJlYW0uc3RyZWFtQXJuLFxuICAgICAgICB9LFxuICAgICAgfV0sXG4gICAgICBmaWVsZHM6IFtcbiAgICAgICAgXCJ0aW1lc3RhbXBcIiwgXCJjLWlwXCIsIFwic2Mtc3RhdHVzXCIsIFwiY3MtdXJpLXN0ZW1cIiwgXCJjcy1tZXRob2RcIixcbiAgICAgICAgXCJjcy1ob3N0XCIsIFwiY3MtdXNlci1hZ2VudFwiLCBcInNjLWJ5dGVzXCIsIFwidGltZS10YWtlblwiLCBcImMtY291bnRyeVwiLFxuICAgICAgXSxcbiAgICB9KTtcblxuICAgIC8vIEF0dGFjaCByZWFsLXRpbWUgbG9ncyB0byB0aGUgZGVmYXVsdCBjYWNoZSBiZWhhdmlvclxuICAgIGNvbnN0IGNmbkRpc3QgPSBkaXN0cmlidXRpb24ubm9kZS5kZWZhdWx0Q2hpbGQgYXMgY2xvdWRmcm9udC5DZm5EaXN0cmlidXRpb247XG4gICAgY2ZuRGlzdC5hZGRQcm9wZXJ0eU92ZXJyaWRlKFxuICAgICAgXCJEaXN0cmlidXRpb25Db25maWcuRGVmYXVsdENhY2hlQmVoYXZpb3IuUmVhbHRpbWVMb2dDb25maWdBcm5cIixcbiAgICAgIHJlYWx0aW1lTG9nQ29uZmlnLmF0dHJBcm5cbiAgICApO1xuXG4gICAgLy8gLS0tIERhc2hib2FyZDogbGlzdCByZXZva2VkIHNlc3Npb25zIGZyb20gS1ZTIC0tLVxuICAgIGNvbnN0IGxpc3RSZXZva2VkID0gbmV3IGxhbWJkYS5GdW5jdGlvbih0aGlzLCBcIkxpc3RSZXZva2VkXCIsIHtcbiAgICAgIHJ1bnRpbWU6IGxhbWJkYS5SdW50aW1lLk5PREVKU18yMl9YLFxuICAgICAgaGFuZGxlcjogXCJsaXN0X3Jldm9rZWQuaGFuZGxlclwiLFxuICAgICAgY29kZTogbGFtYmRhLkNvZGUuZnJvbUFzc2V0KFwibGFtYmRhXCIpLFxuICAgICAgdGltZW91dDogRHVyYXRpb24uc2Vjb25kcygxMCksXG4gICAgICBlbnZpcm9ubWVudDogeyBLVlNfQVJOOiB0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUFybiB9LFxuICAgIH0pO1xuICAgIGxpc3RSZXZva2VkLmFkZFRvUm9sZVBvbGljeShuZXcgaWFtLlBvbGljeVN0YXRlbWVudCh7XG4gICAgICBhY3Rpb25zOiBbXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6TGlzdEtleXNcIiwgXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6RGVzY3JpYmVLZXlWYWx1ZVN0b3JlXCJdLFxuICAgICAgcmVzb3VyY2VzOiBbdGhpcy5rdlN0b3JlLmtleVZhbHVlU3RvcmVBcm5dLFxuICAgIH0pKTtcblxuICAgIC8vIEFkZCAvcmV2b2tlZCB0byB0aGUgZXhpc3RpbmcgQVBJXG4gICAgYXBpLnJvb3QuYWRkUmVzb3VyY2UoXCJyZXZva2VkXCIpLmFkZE1ldGhvZChcIkdFVFwiLFxuICAgICAgbmV3IGFwaWdhdGV3YXkuTGFtYmRhSW50ZWdyYXRpb24obGlzdFJldm9rZWQpXG4gICAgKTtcblxuICAgIC8vIERlcGxveSBkYXNoYm9hcmQgSFRNTCAoYWxvbmdzaWRlIGRlbW8gc2l0ZSBpZiBlbmFibGVkKVxuICAgIGlmIChjb25maWcubWFpbi5lbmFibGVEZW1vKSB7XG4gICAgICBuZXcgczNkZXBsb3kuQnVja2V0RGVwbG95bWVudCh0aGlzLCBcIkRlcGxveURhc2hib2FyZFwiLCB7XG4gICAgICAgIHNvdXJjZXM6IFtcbiAgICAgICAgICBzM2RlcGxveS5Tb3VyY2UuYXNzZXQoXCJyZXNvdXJjZXMvZGFzaGJvYXJkXCIpLFxuICAgICAgICAgIHMzZGVwbG95LlNvdXJjZS5kYXRhKFwiY29uZmlnLmpzXCIsXG4gICAgICAgICAgICBgd2luZG93LkNUQV9DT05GSUc9e2FwaUVuZHBvaW50OlwiJHthcGkudXJsLnJlcGxhY2UoL1xcLyQvLCcnKX1cIixjZG5Eb21haW46XCJodHRwczovLyR7ZGlzdHJpYnV0aW9uLmRpc3RyaWJ1dGlvbkRvbWFpbk5hbWV9XCJ9O2BcbiAgICAgICAgICApLFxuICAgICAgICBdLFxuICAgICAgICBkZXN0aW5hdGlvbkJ1Y2tldDogZGVtb0J1Y2tldCEsXG4gICAgICAgIGRlc3RpbmF0aW9uS2V5UHJlZml4OiBcIndlYnNpdGVcIixcbiAgICAgICAgcHJ1bmU6IGZhbHNlLFxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLy8gLS0tIEtWUyBDbGVhbnVwOiBwdXJnZSBleHBpcmVkIHJldm9jYXRpb25zIG9uIGEgc2NoZWR1bGUgLS0tXG4gICAgY29uc3Qga3ZzQ2xlYW51cCA9IG5ldyBsYW1iZGEuRnVuY3Rpb24odGhpcywgXCJLdnNDbGVhbnVwXCIsIHtcbiAgICAgIHJ1bnRpbWU6IGxhbWJkYS5SdW50aW1lLk5PREVKU18yMl9YLFxuICAgICAgaGFuZGxlcjogXCJrdnNfY2xlYW51cC5oYW5kbGVyXCIsXG4gICAgICBjb2RlOiBsYW1iZGEuQ29kZS5mcm9tQXNzZXQoXCJsYW1iZGFcIiksXG4gICAgICB0aW1lb3V0OiBEdXJhdGlvbi5taW51dGVzKDIpLFxuICAgICAgZW52aXJvbm1lbnQ6IHsgS1ZTX0FSTjogdGhpcy5rdlN0b3JlLmtleVZhbHVlU3RvcmVBcm4sIFRUTF9IT1VSUzogXCIyNFwiIH0sXG4gICAgfSk7XG4gICAga3ZzQ2xlYW51cC5hZGRUb1JvbGVQb2xpY3kobmV3IGlhbS5Qb2xpY3lTdGF0ZW1lbnQoe1xuICAgICAgYWN0aW9uczogW1wiY2xvdWRmcm9udC1rZXl2YWx1ZXN0b3JlOkxpc3RLZXlzXCIsIFwiY2xvdWRmcm9udC1rZXl2YWx1ZXN0b3JlOkRlbGV0ZUtleVwiLCBcImNsb3VkZnJvbnQta2V5dmFsdWVzdG9yZTpEZXNjcmliZUtleVZhbHVlU3RvcmVcIl0sXG4gICAgICByZXNvdXJjZXM6IFt0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUFybl0sXG4gICAgfSkpO1xuICAgIG5ldyBldmVudHMuUnVsZSh0aGlzLCBcIkt2c0NsZWFudXBTY2hlZHVsZVwiLCB7XG4gICAgICBzY2hlZHVsZTogZXZlbnRzLlNjaGVkdWxlLnJhdGUoRHVyYXRpb24uaG91cnMoMSkpLFxuICAgICAgdGFyZ2V0czogW25ldyB0YXJnZXRzLkxhbWJkYUZ1bmN0aW9uKGt2c0NsZWFudXApXSxcbiAgICB9KTtcblxuICAgIC8vIE91dHB1dHNcbiAgICBuZXcgQ2ZuT3V0cHV0KHRoaXMsIFwiQVBJRW5kcG9pbnRcIiwgeyBcbiAgICAgIHZhbHVlOiBgaHR0cHM6Ly8ke2Rpc3RyaWJ1dGlvbi5kaXN0cmlidXRpb25Eb21haW5OYW1lfS9hcGlgLFxuICAgICAgZGVzY3JpcHRpb246IFwiQ1RBIEFQSSBFbmRwb2ludFwiXG4gICAgfSk7XG4gICAgXG4gICAgaWYgKGNvbmZpZy5tYWluLmVuYWJsZURlbW8pIHtcbiAgICAgIG5ldyBDZm5PdXRwdXQodGhpcywgXCJEZW1vV2Vic2l0ZVVybFwiLCB7IFxuICAgICAgICB2YWx1ZTogYGh0dHBzOi8vJHtkaXN0cmlidXRpb24uZGlzdHJpYnV0aW9uRG9tYWluTmFtZX0vd2Vic2l0ZS9pbmRleC1wYXRoLmh0bWxgLFxuICAgICAgICBkZXNjcmlwdGlvbjogXCJDVEEgRGVtbyBXZWJzaXRlIOKAlCBQYXRoIFRva2VuIE1vZGVcIlxuICAgICAgfSk7XG4gICAgICBuZXcgQ2ZuT3V0cHV0KHRoaXMsIFwiRGVtb1dlYnNpdGVIZWFkZXJVcmxcIiwgeyBcbiAgICAgICAgdmFsdWU6IGBodHRwczovLyR7ZGlzdHJpYnV0aW9uLmRpc3RyaWJ1dGlvbkRvbWFpbk5hbWV9L3dlYnNpdGUvaW5kZXgtaGVhZGVyLmh0bWxgLFxuICAgICAgICBkZXNjcmlwdGlvbjogXCJDVEEgRGVtbyBXZWJzaXRlIOKAlCBIZWFkZXItT25seSBUb2tlbiBNb2RlXCJcbiAgICAgIH0pO1xuICAgICAgbmV3IENmbk91dHB1dCh0aGlzLCBcIkRlbW9XZWJzaXRlSHlicmlkVXJsXCIsIHsgXG4gICAgICAgIHZhbHVlOiBgaHR0cHM6Ly8ke2Rpc3RyaWJ1dGlvbi5kaXN0cmlidXRpb25Eb21haW5OYW1lfS93ZWJzaXRlL2luZGV4LWh5YnJpZC5odG1sYCxcbiAgICAgICAgZGVzY3JpcHRpb246IFwiQ1RBIERlbW8gV2Vic2l0ZSDigJQgSHlicmlkIChQYXRoIEluaXQg4oaSIEhlYWRlciBSZW5ld2FsKVwiXG4gICAgICB9KTtcbiAgICAgIG5ldyBDZm5PdXRwdXQodGhpcywgXCJEYXNoYm9hcmRVcmxcIiwgeyBcbiAgICAgICAgdmFsdWU6IGBodHRwczovLyR7ZGlzdHJpYnV0aW9uLmRpc3RyaWJ1dGlvbkRvbWFpbk5hbWV9L3dlYnNpdGUvZGFzaGJvYXJkLmh0bWxgLFxuICAgICAgICBkZXNjcmlwdGlvbjogXCJSZXZvY2F0aW9uIERhc2hib2FyZCB3aXRoIEJlZHJvY2sgUHJvbXB0IEVkaXRvclwiXG4gICAgICB9KTtcbiAgICB9XG4gICAgXG4gICAgbmV3IENmbk91dHB1dCh0aGlzLCBcIktleVZhbHVlU3RvcmVJZFwiLCB7IFxuICAgICAgdmFsdWU6IHRoaXMua3ZTdG9yZS5rZXlWYWx1ZVN0b3JlSWQsXG4gICAgICBkZXNjcmlwdGlvbjogXCJDbG91ZEZyb250IEtleVZhbHVlU3RvcmUgSURcIlxuICAgIH0pO1xuXG4gICAgbmV3IENmbk91dHB1dCh0aGlzLCBcIlNlY3JldEFyblwiLCB7XG4gICAgICB2YWx1ZTogc2lnbmluZ1NlY3JldC5zZWNyZXRBcm4sXG4gICAgICBkZXNjcmlwdGlvbjogXCJDVEEgc2lnbmluZyBzZWNyZXQgQVJOXCJcbiAgICB9KTtcblxuICAgIG5ldyBDZm5PdXRwdXQodGhpcywgXCJDVEFTdGFuZGFyZFwiLCB7XG4gICAgICB2YWx1ZTogXCJDVEEtNTAwNy1CXCIsXG4gICAgICBkZXNjcmlwdGlvbjogXCJJbXBsZW1lbnRlZCBzdGFuZGFyZCB2ZXJzaW9uXCJcbiAgICB9KTtcblxuICAgIG5ldyBDZm5PdXRwdXQodGhpcywgXCJSb3RhdGlvbldvcmtmbG93XCIsIHtcbiAgICAgIHZhbHVlOiByb3RhdGlvbldvcmtmbG93LnN0YXRlTWFjaGluZU5hbWUsXG4gICAgICBkZXNjcmlwdGlvbjogXCJLZXkgcm90YXRpb24gU3RlcCBGdW5jdGlvbnMgd29ya2Zsb3dcIlxuICAgIH0pO1xuXG4gICAgbmV3IENmbk91dHB1dCh0aGlzLCBcIldlYkFjbEFyblwiLCB7XG4gICAgICB2YWx1ZTogd2ViQWNsLmF0dHJBcm4sXG4gICAgICBkZXNjcmlwdGlvbjogXCJXQUZ2MiBXZWIgQUNMIOKAlCByYXRlLWxpbWl0cyBQT1NUIC9hcGkvdG9rZW5cIlxuICAgIH0pO1xuICB9XG5cbiAgcHJpdmF0ZSBwYXJzZVJvdGF0aW9uUmF0ZShyYXRlOiBzdHJpbmcpOiBEdXJhdGlvbiB7XG4gICAgY29uc3QgbWF0Y2ggPSByYXRlLm1hdGNoKC9eKFxcZCspKFttaGRdKSQvKTtcbiAgICBpZiAoIW1hdGNoKSByZXR1cm4gRHVyYXRpb24uZGF5cygzMCk7XG4gICAgY29uc3QgdmFsdWUgPSBwYXJzZUludChtYXRjaFsxXSk7XG4gICAgc3dpdGNoIChtYXRjaFsyXSkge1xuICAgICAgY2FzZSAnbSc6IHJldHVybiBEdXJhdGlvbi5taW51dGVzKHZhbHVlKTtcbiAgICAgIGNhc2UgJ2gnOiByZXR1cm4gRHVyYXRpb24uaG91cnModmFsdWUpO1xuICAgICAgY2FzZSAnZCc6IHJldHVybiBEdXJhdGlvbi5kYXlzKHZhbHVlKTtcbiAgICAgIGRlZmF1bHQ6IHJldHVybiBEdXJhdGlvbi5kYXlzKDMwKTtcbiAgICB9XG4gIH1cbn1cbiJdfQ==