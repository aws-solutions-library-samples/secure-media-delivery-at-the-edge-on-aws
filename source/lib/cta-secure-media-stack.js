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
        // CTA validator function
        const validator = new aws_cdk_lib_1.aws_cloudfront.Function(this, "CTAValidator", {
            code: aws_cdk_lib_1.aws_cloudfront.FunctionCode.fromFile({ filePath: "lambda/cta_token_validator.js" }),
            functionName: `${aws_cdk_lib_1.Aws.STACK_NAME}-CTA-Validator`,
            runtime: aws_cdk_lib_1.aws_cloudfront.FunctionRuntime.JS_2_0,
            keyValueStore: this.kvStore,
        });
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
                defaultBehavior: {
                    origin: new aws_cloudfront_origins_1.HttpOrigin("cdn.mediaplaypen.com"),
                    viewerProtocolPolicy: aws_cdk_lib_1.aws_cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                    cachePolicy: new aws_cdk_lib_1.aws_cloudfront.CachePolicy(this, "CTACachePolicy", {
                        headerBehavior: aws_cdk_lib_1.aws_cloudfront.CacheHeaderBehavior.allowList("CloudFront-Viewer-Country"),
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
                value: `https://${distribution.distributionDomainName}/website/index.html`,
                description: "CTA Demo Website URL"
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY3RhLXNlY3VyZS1tZWRpYS1zdGFjay5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbImN0YS1zZWN1cmUtbWVkaWEtc3RhY2sudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsNkNBc0JxQjtBQUVyQiwrRUFBK0Y7QUFDL0YscUVBQStEO0FBTy9ELE1BQWEsbUJBQW9CLFNBQVEsbUJBQUs7SUFNNUMsWUFBWSxLQUFnQixFQUFFLEVBQVUsRUFBRSxRQUFrQyxFQUFFO1FBQzVFLEtBQUssQ0FBQyxLQUFLLEVBQUUsRUFBRSxFQUFFLEtBQUssQ0FBQyxDQUFDO1FBRXhCLE1BQU0sVUFBVSxHQUFHLElBQUksMEJBQVksQ0FBQyxJQUFJLEVBQUUsWUFBWSxFQUFFO1lBQ3RELElBQUksRUFBRSxRQUFRO1lBQ2QsT0FBTyxFQUFFLE1BQU07WUFDZixhQUFhLEVBQUUsQ0FBQyxNQUFNLEVBQUUsT0FBTyxDQUFDO1lBQ2hDLFdBQVcsRUFBRSxxQkFBcUI7U0FDbkMsQ0FBQyxDQUFDO1FBRUgsTUFBTSxZQUFZLEdBQUcsSUFBSSwwQkFBWSxDQUFDLElBQUksRUFBRSxjQUFjLEVBQUU7WUFDMUQsSUFBSSxFQUFFLFFBQVE7WUFDZCxPQUFPLEVBQUUsdUJBQXVCO1lBQ2hDLGFBQWEsRUFBRSxDQUFDLHNCQUFzQixFQUFFLHVCQUF1QixDQUFDO1lBQ2hFLFdBQVcsRUFBRSwrQkFBK0I7U0FDN0MsQ0FBQyxDQUFDO1FBRUgsTUFBTSxNQUFNLEdBQUcsS0FBSyxDQUFDLE1BQU0sSUFBSTtZQUM3QixJQUFJLEVBQUU7Z0JBQ0osVUFBVSxFQUFFLFVBQVUsQ0FBQyxhQUFhLEtBQUssTUFBTTthQUNoRDtZQUNELE9BQU8sRUFBRTtnQkFDUCxLQUFLLEVBQUUsWUFBWSxDQUFDLGFBQWE7YUFDbEM7U0FDRixDQUFDO1FBRUYsa0JBQWtCO1FBQ2xCLE1BQU0sYUFBYSxHQUFHLElBQUksZ0NBQWMsQ0FBQyxNQUFNLENBQUMsSUFBSSxFQUFFLFFBQVEsRUFBRTtZQUM5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QUMsQ0FBQyxPQUFPLHNCQUFRLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxDQUFDO1lBQ3RDLE9BQU8sQ0FBQyxDQUFDLE9BQU8sc0JBQVEsQ0FBQyxJQUFJLENBQUMsRUFBRSxDQUFDLENBQUM7UUFDcEMsQ0FBQztJQUNILENBQUM7Q0FDRjtBQTlZRCxrREE4WUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQge1xuICBTdGFjayxcbiAgU3RhY2tQcm9wcyxcbiAgQXdzLFxuICBSZW1vdmFsUG9saWN5LFxuICBEdXJhdGlvbixcbiAgQ2ZuT3V0cHV0LFxuICBDZm5QYXJhbWV0ZXIsXG4gIEN1c3RvbVJlc291cmNlLFxuICBhd3NfY2xvdWRmcm9udCBhcyBjbG91ZGZyb250LFxuICBhd3NfbGFtYmRhIGFzIGxhbWJkYSxcbiAgYXdzX2FwaWdhdGV3YXkgYXMgYXBpZ2F0ZXdheSxcbiAgYXdzX3NlY3JldHNtYW5hZ2VyIGFzIHNlY3JldHNtYW5hZ2VyLFxuICBhd3NfczMgYXMgczMsXG4gIGF3c19zM19kZXBsb3ltZW50IGFzIHMzZGVwbG95LFxuICBhd3NfaWFtIGFzIGlhbSxcbiAgYXdzX3N0ZXBmdW5jdGlvbnMgYXMgc2ZuLFxuICBhd3Nfc3RlcGZ1bmN0aW9uc190YXNrcyBhcyB0YXNrcyxcbiAgYXdzX2V2ZW50cyBhcyBldmVudHMsXG4gIGF3c19ldmVudHNfdGFyZ2V0cyBhcyB0YXJnZXRzLFxuICBhd3Nfa2luZXNpcyBhcyBraW5lc2lzLFxuICBjdXN0b21fcmVzb3VyY2VzLFxufSBmcm9tIFwiYXdzLWNkay1saWJcIjtcblxuaW1wb3J0IHsgSHR0cE9yaWdpbiwgUmVzdEFwaU9yaWdpbiwgUzNCdWNrZXRPcmlnaW4gfSBmcm9tIFwiYXdzLWNkay1saWIvYXdzLWNsb3VkZnJvbnQtb3JpZ2luc1wiO1xuaW1wb3J0IHsgTm9kZWpzRnVuY3Rpb24gfSBmcm9tIFwiYXdzLWNkay1saWIvYXdzLWxhbWJkYS1ub2RlanNcIjtcbmltcG9ydCB7IENvbnN0cnVjdCB9IGZyb20gXCJjb25zdHJ1Y3RzXCI7XG5cbmV4cG9ydCBpbnRlcmZhY2UgQ1RBU2VjdXJlTWVkaWFTdGFja1Byb3BzIGV4dGVuZHMgU3RhY2tQcm9wcyB7XG4gIHJlYWRvbmx5IGNvbmZpZz86IGFueTtcbn1cblxuZXhwb3J0IGNsYXNzIENUQVNlY3VyZU1lZGlhU3RhY2sgZXh0ZW5kcyBTdGFjayB7XG4gIHB1YmxpYyByZWFkb25seSBrdlN0b3JlOiBjbG91ZGZyb250LktleVZhbHVlU3RvcmU7XG4gIHB1YmxpYyByZWFkb25seSBkaXN0cmlidXRpb246IGNsb3VkZnJvbnQuRGlzdHJpYnV0aW9uO1xuICBwdWJsaWMgcmVhZG9ubHkgZGVtb0J1Y2tldDogczMuQnVja2V0O1xuICBwdWJsaWMgcmVhZG9ubHkgbG9nU3RyZWFtOiBraW5lc2lzLlN0cmVhbTtcbiAgXG4gIGNvbnN0cnVjdG9yKHNjb3BlOiBDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIHByb3BzOiBDVEFTZWN1cmVNZWRpYVN0YWNrUHJvcHMgPSB7fSkge1xuICAgIHN1cGVyKHNjb3BlLCBpZCwgcHJvcHMpO1xuXG4gICAgY29uc3QgZW5hYmxlRGVtbyA9IG5ldyBDZm5QYXJhbWV0ZXIodGhpcywgXCJFbmFibGVEZW1vXCIsIHtcbiAgICAgIHR5cGU6IFwiU3RyaW5nXCIsXG4gICAgICBkZWZhdWx0OiBcInRydWVcIixcbiAgICAgIGFsbG93ZWRWYWx1ZXM6IFtcInRydWVcIiwgXCJmYWxzZVwiXSxcbiAgICAgIGRlc2NyaXB0aW9uOiBcIkRlcGxveSBkZW1vIHdlYnNpdGVcIixcbiAgICB9KTtcblxuICAgIGNvbnN0IGJlZHJvY2tNb2RlbCA9IG5ldyBDZm5QYXJhbWV0ZXIodGhpcywgXCJCZWRyb2NrTW9kZWxcIiwge1xuICAgICAgdHlwZTogXCJTdHJpbmdcIixcbiAgICAgIGRlZmF1bHQ6IFwiYW1hem9uLm5vdmEtbGl0ZS12MTowXCIsXG4gICAgICBhbGxvd2VkVmFsdWVzOiBbXCJhbWF6b24ubm92YS1wcm8tdjE6MFwiLCBcImFtYXpvbi5ub3ZhLWxpdGUtdjE6MFwiXSxcbiAgICAgIGRlc2NyaXB0aW9uOiBcIkJlZHJvY2sgbW9kZWwgZm9yIEFJIGFuYWx5c2lzXCIsXG4gICAgfSk7XG5cbiAgICBjb25zdCBjb25maWcgPSBwcm9wcy5jb25maWcgfHwge1xuICAgICAgbWFpbjoge1xuICAgICAgICBlbmFibGVEZW1vOiBlbmFibGVEZW1vLnZhbHVlQXNTdHJpbmcgPT09IFwidHJ1ZVwiLFxuICAgICAgfSxcbiAgICAgIGJlZHJvY2s6IHtcbiAgICAgICAgbW9kZWw6IGJlZHJvY2tNb2RlbC52YWx1ZUFzU3RyaW5nLFxuICAgICAgfVxuICAgIH07XG5cbiAgICAvLyBDVEEgc2lnbmluZyBrZXlcbiAgICBjb25zdCBzaWduaW5nU2VjcmV0ID0gbmV3IHNlY3JldHNtYW5hZ2VyLlNlY3JldCh0aGlzLCBcIkNUQUtleVwiLCB7XG4gICAgICBnZW5lcmF0ZVNlY3JldFN0cmluZzoge1xuICAgICAgICBzZWNyZXRTdHJpbmdUZW1wbGF0ZTogJ3tcImFsZ29yaXRobVwiOlwiSE1BQy1TSEEyNTZcIn0nLFxuICAgICAgICBnZW5lcmF0ZVN0cmluZ0tleTogXCJzaWduaW5nS2V5XCIsXG4gICAgICAgIHBhc3N3b3JkTGVuZ3RoOiA2NCxcbiAgICAgIH0sXG4gICAgICByZW1vdmFsUG9saWN5OiBSZW1vdmFsUG9saWN5LkRFU1RST1ksXG4gICAgfSk7XG5cbiAgICAvLyBDbG91ZEZyb250IEtleVZhbHVlU3RvcmUgZm9yIHJldm9jYXRpb25cbiAgICB0aGlzLmt2U3RvcmUgPSBuZXcgY2xvdWRmcm9udC5LZXlWYWx1ZVN0b3JlKHRoaXMsIFwiQ1RBUmV2b2NhdGlvblN0b3JlXCIsIHtcbiAgICAgIGNvbW1lbnQ6IFwiQ1RBIHRva2VuIHJldm9jYXRpb24gbGlzdFwiLFxuICAgIH0pO1xuXG4gICAgLy8gQ1RBIHZhbGlkYXRvciBmdW5jdGlvblxuICAgIGNvbnN0IHZhbGlkYXRvciA9IG5ldyBjbG91ZGZyb250LkZ1bmN0aW9uKHRoaXMsIFwiQ1RBVmFsaWRhdG9yXCIsIHtcbiAgICAgIGNvZGU6IGNsb3VkZnJvbnQuRnVuY3Rpb25Db2RlLmZyb21GaWxlKHsgZmlsZVBhdGg6IFwibGFtYmRhL2N0YV90b2tlbl92YWxpZGF0b3IuanNcIiB9KSxcbiAgICAgIGZ1bmN0aW9uTmFtZTogYCR7QXdzLlNUQUNLX05BTUV9LUNUQS1WYWxpZGF0b3JgLFxuICAgICAgcnVudGltZTogY2xvdWRmcm9udC5GdW5jdGlvblJ1bnRpbWUuSlNfMl8wLFxuICAgICAga2V5VmFsdWVTdG9yZTogdGhpcy5rdlN0b3JlLFxuICAgIH0pO1xuXG4gICAgLy8gVG9rZW4gZ2VuZXJhdG9yIChOb2RlIFNESylcbiAgICAvLyBOb2RlanNGdW5jdGlvbiAoZXNidWlsZCkgYnVuZGxlcyB0aGUgaGFuZGxlciB0b2dldGhlciB3aXRoIGl0c1xuICAgIC8vIHRoaXJkLXBhcnR5IGRlcGVuZGVuY3kgY2Jvci14LCB3aGljaCBpcyBOT1QgcHJvdmlkZWQgYnkgdGhlIExhbWJkYVxuICAgIC8vIE5vZGUuanMgcnVudGltZS4gQSBwbGFpbiBDb2RlLmZyb21Bc3NldChcImxhbWJkYVwiKSBzaGlwcyBubyBub2RlX21vZHVsZXMsXG4gICAgLy8gc28gcmVxdWlyZSgnY2Jvci14JykgZmFpbHMgYXQgbW9kdWxlIGluaXQgYW5kIEFQSSBHYXRld2F5IHJldHVybnMgYSA1MDJcbiAgICAvLyB3aXRoIG5vIENPUlMgaGVhZGVycyDigJQgc3VyZmFjaW5nIGluIHRoZSBicm93c2VyIGFzIGEgQ09SUyBlcnJvci5cbiAgICAvLyBUaGUgQVdTIFNESyB2MyBwYWNrYWdlcyAoQGF3cy1zZGsvKikgcmVtYWluIGV4dGVybmFsaXplZCBieSBkZWZhdWx0XG4gICAgLy8gc2luY2UgdGhleSBBUkUgcHJlc2VudCBpbiB0aGUgcnVudGltZS5cbiAgICBjb25zdCBnZW5lcmF0b3IgPSBuZXcgTm9kZWpzRnVuY3Rpb24odGhpcywgXCJDVEFHZW5lcmF0b3JcIiwge1xuICAgICAgcnVudGltZTogbGFtYmRhLlJ1bnRpbWUuTk9ERUpTXzIyX1gsXG4gICAgICBlbnRyeTogXCJsYW1iZGEvY3RhX3Rva2VuX2dlbmVyYXRvci5qc1wiLFxuICAgICAgaGFuZGxlcjogXCJoYW5kbGVyXCIsXG4gICAgICB0aW1lb3V0OiBEdXJhdGlvbi5zZWNvbmRzKDEwKSxcbiAgICAgIGVudmlyb25tZW50OiB7IFNFQ1JFVF9OQU1FOiBzaWduaW5nU2VjcmV0LnNlY3JldE5hbWUgfSxcbiAgICB9KTtcblxuICAgIC8vIFRva2VuIGdlbmVyYXRvciAoUHl0aG9uIFNESylcbiAgICBjb25zdCBnZW5lcmF0b3JQeXRob24gPSBuZXcgbGFtYmRhLkZ1bmN0aW9uKHRoaXMsIFwiQ1RBR2VuZXJhdG9yUHl0aG9uXCIsIHtcbiAgICAgIHJ1bnRpbWU6IGxhbWJkYS5SdW50aW1lLlBZVEhPTl8zXzEzLFxuICAgICAgaGFuZGxlcjogXCJoYW5kbGVyLmhhbmRsZXJcIixcbiAgICAgIGNvZGU6IGxhbWJkYS5Db2RlLmZyb21Bc3NldChcImxhbWJkYS1weXRob25cIiksXG4gICAgICB0aW1lb3V0OiBEdXJhdGlvbi5zZWNvbmRzKDEwKSxcbiAgICAgIGVudmlyb25tZW50OiB7IFNFQ1JFVF9OQU1FOiBzaWduaW5nU2VjcmV0LnNlY3JldE5hbWUgfSxcbiAgICB9KTtcblxuICAgIC8vIFRva2VuIGdlbmVyYXRvciAoUnVieSBTREspXG4gICAgY29uc3QgZ2VuZXJhdG9yUnVieSA9IG5ldyBsYW1iZGEuRnVuY3Rpb24odGhpcywgXCJDVEFHZW5lcmF0b3JSdWJ5XCIsIHtcbiAgICAgIHJ1bnRpbWU6IGxhbWJkYS5SdW50aW1lLlJVQllfM18zLFxuICAgICAgaGFuZGxlcjogXCJoYW5kbGVyLmhhbmRsZXJcIixcbiAgICAgIGNvZGU6IGxhbWJkYS5Db2RlLmZyb21Bc3NldChcImxhbWJkYS1ydWJ5XCIpLFxuICAgICAgdGltZW91dDogRHVyYXRpb24uc2Vjb25kcygxMCksXG4gICAgICBlbnZpcm9ubWVudDogeyBTRUNSRVRfTkFNRTogc2lnbmluZ1NlY3JldC5zZWNyZXROYW1lIH0sXG4gICAgfSk7XG5cbiAgICAvLyBUb2tlbiByZXZvY2F0aW9uIGhhbmRsZXJcbiAgICBjb25zdCByZXZva2VyID0gbmV3IGxhbWJkYS5GdW5jdGlvbih0aGlzLCBcIkNUQVJldm9rZXJcIiwge1xuICAgICAgcnVudGltZTogbGFtYmRhLlJ1bnRpbWUuTk9ERUpTXzIyX1gsXG4gICAgICBoYW5kbGVyOiBcImN0YV9yZXZvY2F0aW9uLmhhbmRsZXJcIixcbiAgICAgIGNvZGU6IGxhbWJkYS5Db2RlLmZyb21Bc3NldChcImxhbWJkYVwiKSxcbiAgICAgIHRpbWVvdXQ6IER1cmF0aW9uLnNlY29uZHMoMTApLFxuICAgICAgZW52aXJvbm1lbnQ6IHsgS1ZTX0FSTjogdGhpcy5rdlN0b3JlLmtleVZhbHVlU3RvcmVBcm4gfSxcbiAgICB9KTtcblxuICAgIHNpZ25pbmdTZWNyZXQuZ3JhbnRSZWFkKGdlbmVyYXRvcik7XG4gICAgc2lnbmluZ1NlY3JldC5ncmFudFJlYWQoZ2VuZXJhdG9yUHl0aG9uKTtcbiAgICBzaWduaW5nU2VjcmV0LmdyYW50UmVhZChnZW5lcmF0b3JSdWJ5KTtcblxuICAgIC8vIEdyYW50IEtWUyB1cGRhdGUgcGVybWlzc2lvbiB2aWEgSUFNIHBvbGljeVxuICAgIHJldm9rZXIuYWRkVG9Sb2xlUG9saWN5KG5ldyBpYW0uUG9saWN5U3RhdGVtZW50KHtcbiAgICAgIGVmZmVjdDogaWFtLkVmZmVjdC5BTExPVyxcbiAgICAgIGFjdGlvbnM6IFtcImNsb3VkZnJvbnQta2V5dmFsdWVzdG9yZTpQdXRLZXlcIiwgXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6RGVzY3JpYmVLZXlWYWx1ZVN0b3JlXCJdLFxuICAgICAgcmVzb3VyY2VzOiBbdGhpcy5rdlN0b3JlLmtleVZhbHVlU3RvcmVBcm5dLFxuICAgIH0pKTtcblxuICAgIC8vIC0tLSBLZXkgc3luYyBMYW1iZGEgKGN1c3RvbSByZXNvdXJjZSArIHJvdGF0aW9uKSAtLS1cbiAgICBjb25zdCBzeW5jS2V5c1RvS3ZzID0gbmV3IGxhbWJkYS5GdW5jdGlvbih0aGlzLCBcIlN5bmNLZXlzVG9LdnNcIiwge1xuICAgICAgcnVudGltZTogbGFtYmRhLlJ1bnRpbWUuTk9ERUpTXzIyX1gsXG4gICAgICBoYW5kbGVyOiBcImluZGV4LmhhbmRsZXJcIixcbiAgICAgIGNvZGU6IGxhbWJkYS5Db2RlLmZyb21Bc3NldChcImxhbWJkYS9zeW5jX2tleXNcIiksXG4gICAgICB0aW1lb3V0OiBEdXJhdGlvbi5zZWNvbmRzKDMwKSxcbiAgICAgIGVudmlyb25tZW50OiB7XG4gICAgICAgIFNFQ1JFVF9OQU1FOiBzaWduaW5nU2VjcmV0LnNlY3JldE5hbWUsXG4gICAgICAgIEtWU19BUk46IHRoaXMua3ZTdG9yZS5rZXlWYWx1ZVN0b3JlQXJuLFxuICAgICAgfSxcbiAgICB9KTtcblxuICAgIHNpZ25pbmdTZWNyZXQuZ3JhbnRSZWFkKHN5bmNLZXlzVG9LdnMpO1xuICAgIHNpZ25pbmdTZWNyZXQuZ3JhbnRXcml0ZShzeW5jS2V5c1RvS3ZzKTtcbiAgICBzeW5jS2V5c1RvS3ZzLmFkZFRvUm9sZVBvbGljeShuZXcgaWFtLlBvbGljeVN0YXRlbWVudCh7XG4gICAgICBlZmZlY3Q6IGlhbS5FZmZlY3QuQUxMT1csXG4gICAgICBhY3Rpb25zOiBbXG4gICAgICAgIFwiY2xvdWRmcm9udC1rZXl2YWx1ZXN0b3JlOlB1dEtleVwiLFxuICAgICAgICBcImNsb3VkZnJvbnQta2V5dmFsdWVzdG9yZTpEZXNjcmliZUtleVZhbHVlU3RvcmVcIixcbiAgICAgIF0sXG4gICAgICByZXNvdXJjZXM6IFt0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUFybl0sXG4gICAgfSkpO1xuXG4gICAgLy8gQ3VzdG9tIHJlc291cmNlOiBzeW5jIGtleSB0byBLVlMgb24gZGVwbG95XG4gICAgY29uc3Qga2V5U3luY1Byb3ZpZGVyID0gbmV3IGN1c3RvbV9yZXNvdXJjZXMuUHJvdmlkZXIodGhpcywgXCJLZXlTeW5jUHJvdmlkZXJcIiwge1xuICAgICAgb25FdmVudEhhbmRsZXI6IHN5bmNLZXlzVG9LdnMsXG4gICAgfSk7XG5cbiAgICBuZXcgQ3VzdG9tUmVzb3VyY2UodGhpcywgXCJLZXlTeW5jUmVzb3VyY2VcIiwge1xuICAgICAgc2VydmljZVRva2VuOiBrZXlTeW5jUHJvdmlkZXIuc2VydmljZVRva2VuLFxuICAgICAgcHJvcGVydGllczoge1xuICAgICAgICAvLyBGb3JjZSB1cGRhdGUgb24gZWFjaCBkZXBsb3kgdG8gZW5zdXJlIGtleSBpcyBzeW5jZWRcbiAgICAgICAgVGltZXN0YW1wOiBEYXRlLm5vdygpLnRvU3RyaW5nKCksXG4gICAgICB9LFxuICAgIH0pO1xuXG4gICAgLy8gLS0tIEtleSByb3RhdGlvbiB3b3JrZmxvdyAtLS1cbiAgICBjb25zdCByb3RhdGVLZXlUYXNrID0gbmV3IHRhc2tzLkxhbWJkYUludm9rZSh0aGlzLCBcIlJvdGF0ZVNpZ25pbmdLZXlcIiwge1xuICAgICAgbGFtYmRhRnVuY3Rpb246IHN5bmNLZXlzVG9LdnMsXG4gICAgICBwYXlsb2FkOiBzZm4uVGFza0lucHV0LmZyb21PYmplY3QoeyByb3RhdGU6IHRydWUgfSksXG4gICAgICByZXN1bHRQYXRoOiBzZm4uSnNvblBhdGguRElTQ0FSRCxcbiAgICB9KTtcblxuICAgIGNvbnN0IHJvdGF0aW9uV29ya2Zsb3cgPSBuZXcgc2ZuLlN0YXRlTWFjaGluZSh0aGlzLCBcIktleVJvdGF0aW9uV29ya2Zsb3dcIiwge1xuICAgICAgc3RhdGVNYWNoaW5lTmFtZTogYCR7QXdzLlNUQUNLX05BTUV9X1JvdGF0ZUtleXNgLFxuICAgICAgZGVmaW5pdGlvbkJvZHk6IHNmbi5EZWZpbml0aW9uQm9keS5mcm9tQ2hhaW5hYmxlKHJvdGF0ZUtleVRhc2spLFxuICAgICAgdGltZW91dDogRHVyYXRpb24ubWludXRlcyg1KSxcbiAgICB9KTtcblxuICAgIC8vIFJvdGF0ZSBrZXlzIG1vbnRobHkgYnkgZGVmYXVsdFxuICAgIGNvbnN0IHJvdGF0aW9uU2NoZWR1bGUgPSBjb25maWcubWFpbi5yb3RhdGlvbkZyZXF1ZW5jeSB8fCBcIjMwZFwiO1xuICAgIGNvbnN0IHJvdGF0aW9uUmF0ZSA9IHRoaXMucGFyc2VSb3RhdGlvblJhdGUocm90YXRpb25TY2hlZHVsZSk7XG4gICAgbmV3IGV2ZW50cy5SdWxlKHRoaXMsIFwiS2V5Um90YXRpb25TY2hlZHVsZVwiLCB7XG4gICAgICBzY2hlZHVsZTogZXZlbnRzLlNjaGVkdWxlLnJhdGUocm90YXRpb25SYXRlKSxcbiAgICAgIHRhcmdldHM6IFtuZXcgdGFyZ2V0cy5TZm5TdGF0ZU1hY2hpbmUocm90YXRpb25Xb3JrZmxvdyldLFxuICAgIH0pO1xuXG4gICAgLy8gQVBJIEdhdGV3YXlcbiAgICBjb25zdCBhcGkgPSBuZXcgYXBpZ2F0ZXdheS5SZXN0QXBpKHRoaXMsIFwiQ1RBQVBJXCIsIHtcbiAgICAgIHJlc3RBcGlOYW1lOiBcIkNUQSBUb2tlbiBBUElcIixcbiAgICAgIGRlZmF1bHRDb3JzUHJlZmxpZ2h0T3B0aW9uczoge1xuICAgICAgICBhbGxvd09yaWdpbnM6IGFwaWdhdGV3YXkuQ29ycy5BTExfT1JJR0lOUyxcbiAgICAgICAgYWxsb3dNZXRob2RzOiBhcGlnYXRld2F5LkNvcnMuQUxMX01FVEhPRFMsXG4gICAgICB9LFxuICAgIH0pO1xuXG4gICAgLy8gQXR0YWNoIENPUlMgaGVhZGVycyB0byBBUEkgR2F0ZXdheSdzIGRlZmF1bHQgZ2F0ZXdheSByZXNwb25zZXMgc28gdGhhdFxuICAgIC8vIGludGVncmF0aW9uIGVycm9ycyAoZS5nLiBhIExhbWJkYSA1eHgvdGltZW91dCwgb3IgYSA0eHgpIHN0aWxsIGNhcnJ5XG4gICAgLy8gQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luLiBXaXRob3V0IHRoaXMsIGFuIGVycm9yZWQgcmVxdWVzdCByZXR1cm5zIGFcbiAgICAvLyByZXNwb25zZSB3aXRoIG5vIENPUlMgaGVhZGVyLCB3aGljaCBicm93c2VycyBzdXJmYWNlIGFzIGEgbWlzbGVhZGluZ1xuICAgIC8vIFwiYmxvY2tlZCBieSBDT1JTIHBvbGljeVwiIGVycm9yIHRoYXQgbWFza3MgdGhlIHJlYWwgc3RhdHVzIGNvZGUuXG4gICAgY29uc3QgY29yc1Jlc3BvbnNlSGVhZGVycyA9IHtcbiAgICAgIFwiQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luXCI6IFwiJyonXCIsXG4gICAgICBcIkFjY2Vzcy1Db250cm9sLUFsbG93LUhlYWRlcnNcIjogXCInKidcIixcbiAgICB9O1xuICAgIGFwaS5hZGRHYXRld2F5UmVzcG9uc2UoXCJEZWZhdWx0NFhYXCIsIHtcbiAgICAgIHR5cGU6IGFwaWdhdGV3YXkuUmVzcG9uc2VUeXBlLkRFRkFVTFRfNFhYLFxuICAgICAgcmVzcG9uc2VIZWFkZXJzOiBjb3JzUmVzcG9uc2VIZWFkZXJzLFxuICAgIH0pO1xuICAgIGFwaS5hZGRHYXRld2F5UmVzcG9uc2UoXCJEZWZhdWx0NVhYXCIsIHtcbiAgICAgIHR5cGU6IGFwaWdhdGV3YXkuUmVzcG9uc2VUeXBlLkRFRkFVTFRfNVhYLFxuICAgICAgcmVzcG9uc2VIZWFkZXJzOiBjb3JzUmVzcG9uc2VIZWFkZXJzLFxuICAgIH0pO1xuXG4gICAgY29uc3QgdG9rZW5SZXNvdXJjZSA9IGFwaS5yb290LmFkZFJlc291cmNlKFwidG9rZW5cIik7XG4gICAgdG9rZW5SZXNvdXJjZS5hZGRNZXRob2QoXCJQT1NUXCIsIG5ldyBhcGlnYXRld2F5LkxhbWJkYUludGVncmF0aW9uKGdlbmVyYXRvcikpO1xuXG4gICAgY29uc3QgdG9rZW5QeXRob25SZXNvdXJjZSA9IGFwaS5yb290LmFkZFJlc291cmNlKFwidG9rZW4tcHl0aG9uXCIpO1xuICAgIHRva2VuUHl0aG9uUmVzb3VyY2UuYWRkTWV0aG9kKFwiUE9TVFwiLCBuZXcgYXBpZ2F0ZXdheS5MYW1iZGFJbnRlZ3JhdGlvbihnZW5lcmF0b3JQeXRob24pKTtcblxuICAgIGNvbnN0IHRva2VuUnVieVJlc291cmNlID0gYXBpLnJvb3QuYWRkUmVzb3VyY2UoXCJ0b2tlbi1ydWJ5XCIpO1xuICAgIHRva2VuUnVieVJlc291cmNlLmFkZE1ldGhvZChcIlBPU1RcIiwgbmV3IGFwaWdhdGV3YXkuTGFtYmRhSW50ZWdyYXRpb24oZ2VuZXJhdG9yUnVieSkpO1xuICAgIFxuICAgIGNvbnN0IHJldm9rZVJlc291cmNlID0gYXBpLnJvb3QuYWRkUmVzb3VyY2UoXCJyZXZva2VcIik7XG4gICAgcmV2b2tlUmVzb3VyY2UuYWRkTWV0aG9kKFwiUE9TVFwiLCBuZXcgYXBpZ2F0ZXdheS5MYW1iZGFJbnRlZ3JhdGlvbihyZXZva2VyKSk7XG5cbiAgICAvLyBEZW1vIHdlYnNpdGUgKGNvbmRpdGlvbmFsKVxuICAgIGxldCBkaXN0cmlidXRpb246IGNsb3VkZnJvbnQuRGlzdHJpYnV0aW9uO1xuICAgIGxldCBkZW1vQnVja2V0OiBzMy5CdWNrZXQgfCB1bmRlZmluZWQ7XG4gICAgXG4gICAgaWYgKGNvbmZpZy5tYWluLmVuYWJsZURlbW8pIHtcbiAgICAgIGRlbW9CdWNrZXQgPSBuZXcgczMuQnVja2V0KHRoaXMsIFwiRGVtb1dlYnNpdGVcIiwge1xuICAgICAgICByZW1vdmFsUG9saWN5OiBSZW1vdmFsUG9saWN5LkRFU1RST1ksXG4gICAgICAgIGF1dG9EZWxldGVPYmplY3RzOiB0cnVlLFxuICAgICAgfSk7XG5cbiAgICAgIG5ldyBzM2RlcGxveS5CdWNrZXREZXBsb3ltZW50KHRoaXMsIFwiRGVwbG95RGVtb1NpdGVcIiwge1xuICAgICAgICBzb3VyY2VzOiBbczNkZXBsb3kuU291cmNlLmFzc2V0KFwicmVzb3VyY2VzL2RlbW8td2Vic2l0ZVwiKV0sXG4gICAgICAgIGRlc3RpbmF0aW9uQnVja2V0OiBkZW1vQnVja2V0LFxuICAgICAgICBkZXN0aW5hdGlvbktleVByZWZpeDogXCJ3ZWJzaXRlXCIsXG4gICAgICAgIHBydW5lOiBmYWxzZSxcbiAgICAgIH0pO1xuXG4gICAgICBkaXN0cmlidXRpb24gPSBuZXcgY2xvdWRmcm9udC5EaXN0cmlidXRpb24odGhpcywgXCJDVEFEaXN0cmlidXRpb25cIiwge1xuICAgICAgICBkZWZhdWx0QmVoYXZpb3I6IHtcbiAgICAgICAgICBvcmlnaW46IG5ldyBIdHRwT3JpZ2luKFwiY2RuLm1lZGlhcGxheXBlbi5jb21cIiksXG4gICAgICAgICAgdmlld2VyUHJvdG9jb2xQb2xpY3k6IGNsb3VkZnJvbnQuVmlld2VyUHJvdG9jb2xQb2xpY3kuUkVESVJFQ1RfVE9fSFRUUFMsXG4gICAgICAgICAgY2FjaGVQb2xpY3k6IG5ldyBjbG91ZGZyb250LkNhY2hlUG9saWN5KHRoaXMsIFwiQ1RBQ2FjaGVQb2xpY3lcIiwge1xuICAgICAgICAgICAgaGVhZGVyQmVoYXZpb3I6IGNsb3VkZnJvbnQuQ2FjaGVIZWFkZXJCZWhhdmlvci5hbGxvd0xpc3QoXG4gICAgICAgICAgICAgIFwiQ2xvdWRGcm9udC1WaWV3ZXItQ291bnRyeVwiXG4gICAgICAgICAgICApLFxuICAgICAgICAgIH0pLFxuICAgICAgICAgIG9yaWdpblJlcXVlc3RQb2xpY3k6IGNsb3VkZnJvbnQuT3JpZ2luUmVxdWVzdFBvbGljeS5BTExfVklFV0VSX0VYQ0VQVF9IT1NUX0hFQURFUixcbiAgICAgICAgICBmdW5jdGlvbkFzc29jaWF0aW9uczogW3tcbiAgICAgICAgICAgIGZ1bmN0aW9uOiB2YWxpZGF0b3IsXG4gICAgICAgICAgICBldmVudFR5cGU6IGNsb3VkZnJvbnQuRnVuY3Rpb25FdmVudFR5cGUuVklFV0VSX1JFUVVFU1QsXG4gICAgICAgICAgfV0sXG4gICAgICAgIH0sXG4gICAgICAgIGFkZGl0aW9uYWxCZWhhdmlvcnM6IHtcbiAgICAgICAgICBcIi9hcGkvKlwiOiB7XG4gICAgICAgICAgICBvcmlnaW46IG5ldyBSZXN0QXBpT3JpZ2luKGFwaSksXG4gICAgICAgICAgICB2aWV3ZXJQcm90b2NvbFBvbGljeTogY2xvdWRmcm9udC5WaWV3ZXJQcm90b2NvbFBvbGljeS5SRURJUkVDVF9UT19IVFRQUyxcbiAgICAgICAgICAgIGFsbG93ZWRNZXRob2RzOiBjbG91ZGZyb250LkFsbG93ZWRNZXRob2RzLkFMTE9XX0FMTCxcbiAgICAgICAgICAgIGNhY2hlUG9saWN5OiBjbG91ZGZyb250LkNhY2hlUG9saWN5LkNBQ0hJTkdfRElTQUJMRUQsXG4gICAgICAgICAgICBvcmlnaW5SZXF1ZXN0UG9saWN5OiBjbG91ZGZyb250Lk9yaWdpblJlcXVlc3RQb2xpY3kuQUxMX1ZJRVdFUl9FWENFUFRfSE9TVF9IRUFERVIsXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcIi93ZWJzaXRlLypcIjoge1xuICAgICAgICAgICAgb3JpZ2luOiBTM0J1Y2tldE9yaWdpbi53aXRoT3JpZ2luQWNjZXNzQ29udHJvbChkZW1vQnVja2V0KSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgfSk7XG5cbiAgICB9IGVsc2Uge1xuICAgICAgZGlzdHJpYnV0aW9uID0gbmV3IGNsb3VkZnJvbnQuRGlzdHJpYnV0aW9uKHRoaXMsIFwiQ1RBRGlzdHJpYnV0aW9uXCIsIHtcbiAgICAgICAgZGVmYXVsdEJlaGF2aW9yOiB7XG4gICAgICAgICAgb3JpZ2luOiBuZXcgUmVzdEFwaU9yaWdpbihhcGkpLFxuICAgICAgICAgIGZ1bmN0aW9uQXNzb2NpYXRpb25zOiBbe1xuICAgICAgICAgICAgZnVuY3Rpb246IHZhbGlkYXRvcixcbiAgICAgICAgICAgIGV2ZW50VHlwZTogY2xvdWRmcm9udC5GdW5jdGlvbkV2ZW50VHlwZS5WSUVXRVJfUkVRVUVTVCxcbiAgICAgICAgICB9XSxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHRoaXMuZGlzdHJpYnV0aW9uID0gZGlzdHJpYnV0aW9uO1xuICAgIGlmIChjb25maWcubWFpbi5lbmFibGVEZW1vKSB7XG4gICAgICB0aGlzLmRlbW9CdWNrZXQgPSBkZW1vQnVja2V0ITtcbiAgICB9XG5cbiAgICAvLyAtLS0gUmVhbC1UaW1lIExvZ2dpbmcgdmlhIEtpbmVzaXMgLS0tXG4gICAgY29uc3QgbG9nU3RyZWFtID0gbmV3IGtpbmVzaXMuU3RyZWFtKHRoaXMsIFwiUmVhbHRpbWVMb2dTdHJlYW1cIiwge1xuICAgICAgc3RyZWFtTW9kZToga2luZXNpcy5TdHJlYW1Nb2RlLk9OX0RFTUFORCxcbiAgICAgIHJldGVudGlvblBlcmlvZDogRHVyYXRpb24uaG91cnMoMjQpLFxuICAgIH0pO1xuICAgIHRoaXMubG9nU3RyZWFtID0gbG9nU3RyZWFtO1xuXG4gICAgY29uc3QgY2ZLaW5lc2lzUm9sZSA9IG5ldyBpYW0uUm9sZSh0aGlzLCBcIkNsb3VkRnJvbnRLaW5lc2lzUm9sZVwiLCB7XG4gICAgICBhc3N1bWVkQnk6IG5ldyBpYW0uU2VydmljZVByaW5jaXBhbChcImNsb3VkZnJvbnQuYW1hem9uYXdzLmNvbVwiKSxcbiAgICB9KTtcbiAgICBsb2dTdHJlYW0uZ3JhbnRXcml0ZShjZktpbmVzaXNSb2xlKTtcblxuICAgIGNvbnN0IHJlYWx0aW1lTG9nQ29uZmlnID0gbmV3IGNsb3VkZnJvbnQuQ2ZuUmVhbHRpbWVMb2dDb25maWcodGhpcywgXCJSZWFsdGltZUxvZ0NvbmZpZ1wiLCB7XG4gICAgICBuYW1lOiBgJHtBd3MuU1RBQ0tfTkFNRX0tcmVhbHRpbWUtbG9nc2AsXG4gICAgICBzYW1wbGluZ1JhdGU6IDEwMCxcbiAgICAgIGVuZFBvaW50czogW3tcbiAgICAgICAgc3RyZWFtVHlwZTogXCJLaW5lc2lzXCIsXG4gICAgICAgIGtpbmVzaXNTdHJlYW1Db25maWc6IHtcbiAgICAgICAgICByb2xlQXJuOiBjZktpbmVzaXNSb2xlLnJvbGVBcm4sXG4gICAgICAgICAgc3RyZWFtQXJuOiBsb2dTdHJlYW0uc3RyZWFtQXJuLFxuICAgICAgICB9LFxuICAgICAgfV0sXG4gICAgICBmaWVsZHM6IFtcbiAgICAgICAgXCJ0aW1lc3RhbXBcIiwgXCJjLWlwXCIsIFwic2Mtc3RhdHVzXCIsIFwiY3MtdXJpLXN0ZW1cIiwgXCJjcy1tZXRob2RcIixcbiAgICAgICAgXCJjcy1ob3N0XCIsIFwiY3MtdXNlci1hZ2VudFwiLCBcInNjLWJ5dGVzXCIsIFwidGltZS10YWtlblwiLCBcImMtY291bnRyeVwiLFxuICAgICAgXSxcbiAgICB9KTtcblxuICAgIC8vIEF0dGFjaCByZWFsLXRpbWUgbG9ncyB0byB0aGUgZGVmYXVsdCBjYWNoZSBiZWhhdmlvclxuICAgIGNvbnN0IGNmbkRpc3QgPSBkaXN0cmlidXRpb24ubm9kZS5kZWZhdWx0Q2hpbGQgYXMgY2xvdWRmcm9udC5DZm5EaXN0cmlidXRpb247XG4gICAgY2ZuRGlzdC5hZGRQcm9wZXJ0eU92ZXJyaWRlKFxuICAgICAgXCJEaXN0cmlidXRpb25Db25maWcuRGVmYXVsdENhY2hlQmVoYXZpb3IuUmVhbHRpbWVMb2dDb25maWdBcm5cIixcbiAgICAgIHJlYWx0aW1lTG9nQ29uZmlnLmF0dHJBcm5cbiAgICApO1xuXG4gICAgLy8gLS0tIERhc2hib2FyZDogbGlzdCByZXZva2VkIHNlc3Npb25zIGZyb20gS1ZTIC0tLVxuICAgIGNvbnN0IGxpc3RSZXZva2VkID0gbmV3IGxhbWJkYS5GdW5jdGlvbih0aGlzLCBcIkxpc3RSZXZva2VkXCIsIHtcbiAgICAgIHJ1bnRpbWU6IGxhbWJkYS5SdW50aW1lLk5PREVKU18yMl9YLFxuICAgICAgaGFuZGxlcjogXCJsaXN0X3Jldm9rZWQuaGFuZGxlclwiLFxuICAgICAgY29kZTogbGFtYmRhLkNvZGUuZnJvbUFzc2V0KFwibGFtYmRhXCIpLFxuICAgICAgdGltZW91dDogRHVyYXRpb24uc2Vjb25kcygxMCksXG4gICAgICBlbnZpcm9ubWVudDogeyBLVlNfQVJOOiB0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUFybiB9LFxuICAgIH0pO1xuICAgIGxpc3RSZXZva2VkLmFkZFRvUm9sZVBvbGljeShuZXcgaWFtLlBvbGljeVN0YXRlbWVudCh7XG4gICAgICBhY3Rpb25zOiBbXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6TGlzdEtleXNcIiwgXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6RGVzY3JpYmVLZXlWYWx1ZVN0b3JlXCJdLFxuICAgICAgcmVzb3VyY2VzOiBbdGhpcy5rdlN0b3JlLmtleVZhbHVlU3RvcmVBcm5dLFxuICAgIH0pKTtcblxuICAgIC8vIEFkZCAvcmV2b2tlZCB0byB0aGUgZXhpc3RpbmcgQVBJXG4gICAgYXBpLnJvb3QuYWRkUmVzb3VyY2UoXCJyZXZva2VkXCIpLmFkZE1ldGhvZChcIkdFVFwiLFxuICAgICAgbmV3IGFwaWdhdGV3YXkuTGFtYmRhSW50ZWdyYXRpb24obGlzdFJldm9rZWQpXG4gICAgKTtcblxuICAgIC8vIERlcGxveSBkYXNoYm9hcmQgSFRNTCAoYWxvbmdzaWRlIGRlbW8gc2l0ZSBpZiBlbmFibGVkKVxuICAgIGlmIChjb25maWcubWFpbi5lbmFibGVEZW1vKSB7XG4gICAgICBuZXcgczNkZXBsb3kuQnVja2V0RGVwbG95bWVudCh0aGlzLCBcIkRlcGxveURhc2hib2FyZFwiLCB7XG4gICAgICAgIHNvdXJjZXM6IFtcbiAgICAgICAgICBzM2RlcGxveS5Tb3VyY2UuYXNzZXQoXCJyZXNvdXJjZXMvZGFzaGJvYXJkXCIpLFxuICAgICAgICAgIHMzZGVwbG95LlNvdXJjZS5kYXRhKFwiY29uZmlnLmpzXCIsXG4gICAgICAgICAgICBgd2luZG93LkNUQV9DT05GSUc9e2FwaUVuZHBvaW50OlwiJHthcGkudXJsLnJlcGxhY2UoL1xcLyQvLCcnKX1cIixjZG5Eb21haW46XCJodHRwczovLyR7ZGlzdHJpYnV0aW9uLmRpc3RyaWJ1dGlvbkRvbWFpbk5hbWV9XCJ9O2BcbiAgICAgICAgICApLFxuICAgICAgICBdLFxuICAgICAgICBkZXN0aW5hdGlvbkJ1Y2tldDogZGVtb0J1Y2tldCEsXG4gICAgICAgIGRlc3RpbmF0aW9uS2V5UHJlZml4OiBcIndlYnNpdGVcIixcbiAgICAgICAgcHJ1bmU6IGZhbHNlLFxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgLy8gLS0tIEtWUyBDbGVhbnVwOiBwdXJnZSBleHBpcmVkIHJldm9jYXRpb25zIG9uIGEgc2NoZWR1bGUgLS0tXG4gICAgY29uc3Qga3ZzQ2xlYW51cCA9IG5ldyBsYW1iZGEuRnVuY3Rpb24odGhpcywgXCJLdnNDbGVhbnVwXCIsIHtcbiAgICAgIHJ1bnRpbWU6IGxhbWJkYS5SdW50aW1lLk5PREVKU18yMl9YLFxuICAgICAgaGFuZGxlcjogXCJrdnNfY2xlYW51cC5oYW5kbGVyXCIsXG4gICAgICBjb2RlOiBsYW1iZGEuQ29kZS5mcm9tQXNzZXQoXCJsYW1iZGFcIiksXG4gICAgICB0aW1lb3V0OiBEdXJhdGlvbi5taW51dGVzKDIpLFxuICAgICAgZW52aXJvbm1lbnQ6IHsgS1ZTX0FSTjogdGhpcy5rdlN0b3JlLmtleVZhbHVlU3RvcmVBcm4sIFRUTF9IT1VSUzogXCIyNFwiIH0sXG4gICAgfSk7XG4gICAga3ZzQ2xlYW51cC5hZGRUb1JvbGVQb2xpY3kobmV3IGlhbS5Qb2xpY3lTdGF0ZW1lbnQoe1xuICAgICAgYWN0aW9uczogW1wiY2xvdWRmcm9udC1rZXl2YWx1ZXN0b3JlOkxpc3RLZXlzXCIsIFwiY2xvdWRmcm9udC1rZXl2YWx1ZXN0b3JlOkRlbGV0ZUtleVwiLCBcImNsb3VkZnJvbnQta2V5dmFsdWVzdG9yZTpEZXNjcmliZUtleVZhbHVlU3RvcmVcIl0sXG4gICAgICByZXNvdXJjZXM6IFt0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUFybl0sXG4gICAgfSkpO1xuICAgIG5ldyBldmVudHMuUnVsZSh0aGlzLCBcIkt2c0NsZWFudXBTY2hlZHVsZVwiLCB7XG4gICAgICBzY2hlZHVsZTogZXZlbnRzLlNjaGVkdWxlLnJhdGUoRHVyYXRpb24uaG91cnMoMSkpLFxuICAgICAgdGFyZ2V0czogW25ldyB0YXJnZXRzLkxhbWJkYUZ1bmN0aW9uKGt2c0NsZWFudXApXSxcbiAgICB9KTtcblxuICAgIC8vIE91dHB1dHNcbiAgICBuZXcgQ2ZuT3V0cHV0KHRoaXMsIFwiQVBJRW5kcG9pbnRcIiwgeyBcbiAgICAgIHZhbHVlOiBgaHR0cHM6Ly8ke2Rpc3RyaWJ1dGlvbi5kaXN0cmlidXRpb25Eb21haW5OYW1lfS9hcGlgLFxuICAgICAgZGVzY3JpcHRpb246IFwiQ1RBIEFQSSBFbmRwb2ludFwiXG4gICAgfSk7XG4gICAgXG4gICAgaWYgKGNvbmZpZy5tYWluLmVuYWJsZURlbW8pIHtcbiAgICAgIG5ldyBDZm5PdXRwdXQodGhpcywgXCJEZW1vV2Vic2l0ZVVybFwiLCB7IFxuICAgICAgICB2YWx1ZTogYGh0dHBzOi8vJHtkaXN0cmlidXRpb24uZGlzdHJpYnV0aW9uRG9tYWluTmFtZX0vd2Vic2l0ZS9pbmRleC5odG1sYCxcbiAgICAgICAgZGVzY3JpcHRpb246IFwiQ1RBIERlbW8gV2Vic2l0ZSBVUkxcIlxuICAgICAgfSk7XG4gICAgfVxuICAgIFxuICAgIG5ldyBDZm5PdXRwdXQodGhpcywgXCJLZXlWYWx1ZVN0b3JlSWRcIiwgeyBcbiAgICAgIHZhbHVlOiB0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUlkLFxuICAgICAgZGVzY3JpcHRpb246IFwiQ2xvdWRGcm9udCBLZXlWYWx1ZVN0b3JlIElEXCJcbiAgICB9KTtcblxuICAgIG5ldyBDZm5PdXRwdXQodGhpcywgXCJTZWNyZXRBcm5cIiwge1xuICAgICAgdmFsdWU6IHNpZ25pbmdTZWNyZXQuc2VjcmV0QXJuLFxuICAgICAgZGVzY3JpcHRpb246IFwiQ1RBIHNpZ25pbmcgc2VjcmV0IEFSTlwiXG4gICAgfSk7XG5cbiAgICBuZXcgQ2ZuT3V0cHV0KHRoaXMsIFwiQ1RBU3RhbmRhcmRcIiwge1xuICAgICAgdmFsdWU6IFwiQ1RBLTUwMDctQlwiLFxuICAgICAgZGVzY3JpcHRpb246IFwiSW1wbGVtZW50ZWQgc3RhbmRhcmQgdmVyc2lvblwiXG4gICAgfSk7XG5cbiAgICBuZXcgQ2ZuT3V0cHV0KHRoaXMsIFwiUm90YXRpb25Xb3JrZmxvd1wiLCB7XG4gICAgICB2YWx1ZTogcm90YXRpb25Xb3JrZmxvdy5zdGF0ZU1hY2hpbmVOYW1lLFxuICAgICAgZGVzY3JpcHRpb246IFwiS2V5IHJvdGF0aW9uIFN0ZXAgRnVuY3Rpb25zIHdvcmtmbG93XCJcbiAgICB9KTtcbiAgfVxuXG4gIHByaXZhdGUgcGFyc2VSb3RhdGlvblJhdGUocmF0ZTogc3RyaW5nKTogRHVyYXRpb24ge1xuICAgIGNvbnN0IG1hdGNoID0gcmF0ZS5tYXRjaCgvXihcXGQrKShbbWhkXSkkLyk7XG4gICAgaWYgKCFtYXRjaCkgcmV0dXJuIER1cmF0aW9uLmRheXMoMzApO1xuICAgIGNvbnN0IHZhbHVlID0gcGFyc2VJbnQobWF0Y2hbMV0pO1xuICAgIHN3aXRjaCAobWF0Y2hbMl0pIHtcbiAgICAgIGNhc2UgJ20nOiByZXR1cm4gRHVyYXRpb24ubWludXRlcyh2YWx1ZSk7XG4gICAgICBjYXNlICdoJzogcmV0dXJuIER1cmF0aW9uLmhvdXJzKHZhbHVlKTtcbiAgICAgIGNhc2UgJ2QnOiByZXR1cm4gRHVyYXRpb24uZGF5cyh2YWx1ZSk7XG4gICAgICBkZWZhdWx0OiByZXR1cm4gRHVyYXRpb24uZGF5cygzMCk7XG4gICAgfVxuICB9XG59XG4iXX0=