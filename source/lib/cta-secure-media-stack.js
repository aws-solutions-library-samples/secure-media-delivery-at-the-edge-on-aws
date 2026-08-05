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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY3RhLXNlY3VyZS1tZWRpYS1zdGFjay5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbImN0YS1zZWN1cmUtbWVkaWEtc3RhY2sudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsNkNBc0JxQjtBQUVyQiwrRUFBK0Y7QUFDL0YscUVBQStEO0FBTy9ELE1BQWEsbUJBQW9CLFNBQVEsbUJBQUs7SUFNNUMsWUFBWSxLQUFnQixFQUFFLEVBQVUsRUFBRSxRQUFrQyxFQUFFO1FBQzVFLEtBQUssQ0FBQyxLQUFLLEVBQUUsRUFBRSxFQUFFLEtBQUssQ0FBQyxDQUFDO1FBRXhCLE1BQU0sVUFBVSxHQUFHLElBQUksMEJBQVksQ0FBQyxJQUFJLEVBQUUsWUFBWSxFQUFFO1lBQ3RELElBQUksRUFBRSxRQUFRO1lBQ2QsT0FBTyxFQUFFLE1BQU07WUFDZixhQUFhLEVBQUUsQ0FBQyxNQUFNLEVBQUUsT0FBTyxDQUFDO1lBQ2hDLFdBQVcsRUFBRSxxQkFBcUI7U0FDbkMsQ0FBQyxDQUFDO1FBRUgsTUFBTSxZQUFZLEdBQUcsSUFBSSwwQkFBWSxDQUFDLElBQUksRUFBRSxjQUFjLEVBQUU7WUFDMUQsSUFBSSxFQUFFLFFBQVE7WUFDZCxPQUFPLEVBQUUsdUJBQXVCO1lBQ2hDLGFBQWEsRUFBRSxDQUFDLHNCQUFzQixFQUFFLHVCQUF1QixDQUFDO1lBQ2hFLFdBQVcsRUFBRSwrQkFBK0I7U0FDN0MsQ0FBQyxDQUFDO1FBRUgsTUFBTSxNQUFNLEdBQUcsS0FBSyxDQUFDLE1BQU0sSUFBSTtZQUM3QixJQUFJLEVBQUU7Z0JBQ0osVUFBVSxFQUFFLFVBQVUsQ0FBQyxhQUFhLEtBQUssTUFBTTthQUNoRDtZQUNELE9BQU8sRUFBRTtnQkFDUCxLQUFLLEVBQUUsWUFBWSxDQUFDLGFBQWE7YUFDbEM7U0FDRixDQUFDO1FBRUYsa0JBQWtCO1FBQ2xCLE1BQU0sYUFBYSxHQUFHLElBQUksZ0NBQWMsQ0FBQyxNQUFNLENBQUMsSUFBSSxFQUFFLFFBQVEsRUFBRTtZQUM5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SSx1QkFBUyxDQUFDLElBQUksRUFBRSxrQkFBa0IsRUFBRTtZQUN0QyxLQUFLLEVBQUUsZ0JBQWdCLENBQUMsZ0JBQWdCO1lBQ3hDLFdBQVcsRUFBRSxzQ0FBc0M7U0FDcEQsQ0FBQyxDQUFDO0lBQ0wsQ0FBQztJQUVPLGlCQUFpQixDQUFDLElBQVk7UUFDcEMsTUFBTSxLQUFLLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDO1FBQzNDLElBQUksQ0FBQyxLQUFLO1lBQUUsT0FBTyxzQkFBUSxDQUFDLElBQUksQ0FBQyxFQUFFLENBQUMsQ0FBQztRQUNyQyxNQUFNLEtBQUssR0FBRyxRQUFRLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7UUFDakMsUUFBUSxLQUFLLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQztZQUNqQixLQUFLLEdBQUcsQ0FBQyxDQUFDLE9BQU8sc0JBQVEsQ0FBQyxPQUFPLENBQUMsS0FBSyxDQUFDLENBQUM7WUFDekMsS0FBSyxHQUFHLENBQUMsQ0FBQyxPQUFPLHNCQUFRLENBQUMsS0FBSyxDQUFDLEtBQUssQ0FBQyxDQUFDO1lBQ3ZDLEtBQUssR0FBRyxDQUFDLENBQUMsT0FBTyxzQkFBUSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUN0QyxPQUFPLENBQUMsQ0FBQyxPQUFPLHNCQUFRLENBQUMsSUFBSSxDQUFDLEVBQUUsQ0FBQyxDQUFDO1FBQ3BDLENBQUM7SUFDSCxDQUFDO0NBQ0Y7QUE1WEQsa0RBNFhDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHtcbiAgU3RhY2ssXG4gIFN0YWNrUHJvcHMsXG4gIEF3cyxcbiAgUmVtb3ZhbFBvbGljeSxcbiAgRHVyYXRpb24sXG4gIENmbk91dHB1dCxcbiAgQ2ZuUGFyYW1ldGVyLFxuICBDdXN0b21SZXNvdXJjZSxcbiAgYXdzX2Nsb3VkZnJvbnQgYXMgY2xvdWRmcm9udCxcbiAgYXdzX2xhbWJkYSBhcyBsYW1iZGEsXG4gIGF3c19hcGlnYXRld2F5IGFzIGFwaWdhdGV3YXksXG4gIGF3c19zZWNyZXRzbWFuYWdlciBhcyBzZWNyZXRzbWFuYWdlcixcbiAgYXdzX3MzIGFzIHMzLFxuICBhd3NfczNfZGVwbG95bWVudCBhcyBzM2RlcGxveSxcbiAgYXdzX2lhbSBhcyBpYW0sXG4gIGF3c19zdGVwZnVuY3Rpb25zIGFzIHNmbixcbiAgYXdzX3N0ZXBmdW5jdGlvbnNfdGFza3MgYXMgdGFza3MsXG4gIGF3c19ldmVudHMgYXMgZXZlbnRzLFxuICBhd3NfZXZlbnRzX3RhcmdldHMgYXMgdGFyZ2V0cyxcbiAgYXdzX2tpbmVzaXMgYXMga2luZXNpcyxcbiAgY3VzdG9tX3Jlc291cmNlcyxcbn0gZnJvbSBcImF3cy1jZGstbGliXCI7XG5cbmltcG9ydCB7IEh0dHBPcmlnaW4sIFJlc3RBcGlPcmlnaW4sIFMzQnVja2V0T3JpZ2luIH0gZnJvbSBcImF3cy1jZGstbGliL2F3cy1jbG91ZGZyb250LW9yaWdpbnNcIjtcbmltcG9ydCB7IE5vZGVqc0Z1bmN0aW9uIH0gZnJvbSBcImF3cy1jZGstbGliL2F3cy1sYW1iZGEtbm9kZWpzXCI7XG5pbXBvcnQgeyBDb25zdHJ1Y3QgfSBmcm9tIFwiY29uc3RydWN0c1wiO1xuXG5leHBvcnQgaW50ZXJmYWNlIENUQVNlY3VyZU1lZGlhU3RhY2tQcm9wcyBleHRlbmRzIFN0YWNrUHJvcHMge1xuICByZWFkb25seSBjb25maWc/OiBhbnk7XG59XG5cbmV4cG9ydCBjbGFzcyBDVEFTZWN1cmVNZWRpYVN0YWNrIGV4dGVuZHMgU3RhY2sge1xuICBwdWJsaWMgcmVhZG9ubHkga3ZTdG9yZTogY2xvdWRmcm9udC5LZXlWYWx1ZVN0b3JlO1xuICBwdWJsaWMgcmVhZG9ubHkgZGlzdHJpYnV0aW9uOiBjbG91ZGZyb250LkRpc3RyaWJ1dGlvbjtcbiAgcHVibGljIHJlYWRvbmx5IGRlbW9CdWNrZXQ6IHMzLkJ1Y2tldDtcbiAgcHVibGljIHJlYWRvbmx5IGxvZ1N0cmVhbToga2luZXNpcy5TdHJlYW07XG4gIFxuICBjb25zdHJ1Y3RvcihzY29wZTogQ29uc3RydWN0LCBpZDogc3RyaW5nLCBwcm9wczogQ1RBU2VjdXJlTWVkaWFTdGFja1Byb3BzID0ge30pIHtcbiAgICBzdXBlcihzY29wZSwgaWQsIHByb3BzKTtcblxuICAgIGNvbnN0IGVuYWJsZURlbW8gPSBuZXcgQ2ZuUGFyYW1ldGVyKHRoaXMsIFwiRW5hYmxlRGVtb1wiLCB7XG4gICAgICB0eXBlOiBcIlN0cmluZ1wiLFxuICAgICAgZGVmYXVsdDogXCJ0cnVlXCIsXG4gICAgICBhbGxvd2VkVmFsdWVzOiBbXCJ0cnVlXCIsIFwiZmFsc2VcIl0sXG4gICAgICBkZXNjcmlwdGlvbjogXCJEZXBsb3kgZGVtbyB3ZWJzaXRlXCIsXG4gICAgfSk7XG5cbiAgICBjb25zdCBiZWRyb2NrTW9kZWwgPSBuZXcgQ2ZuUGFyYW1ldGVyKHRoaXMsIFwiQmVkcm9ja01vZGVsXCIsIHtcbiAgICAgIHR5cGU6IFwiU3RyaW5nXCIsXG4gICAgICBkZWZhdWx0OiBcImFtYXpvbi5ub3ZhLWxpdGUtdjE6MFwiLFxuICAgICAgYWxsb3dlZFZhbHVlczogW1wiYW1hem9uLm5vdmEtcHJvLXYxOjBcIiwgXCJhbWF6b24ubm92YS1saXRlLXYxOjBcIl0sXG4gICAgICBkZXNjcmlwdGlvbjogXCJCZWRyb2NrIG1vZGVsIGZvciBBSSBhbmFseXNpc1wiLFxuICAgIH0pO1xuXG4gICAgY29uc3QgY29uZmlnID0gcHJvcHMuY29uZmlnIHx8IHtcbiAgICAgIG1haW46IHtcbiAgICAgICAgZW5hYmxlRGVtbzogZW5hYmxlRGVtby52YWx1ZUFzU3RyaW5nID09PSBcInRydWVcIixcbiAgICAgIH0sXG4gICAgICBiZWRyb2NrOiB7XG4gICAgICAgIG1vZGVsOiBiZWRyb2NrTW9kZWwudmFsdWVBc1N0cmluZyxcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgLy8gQ1RBIHNpZ25pbmcga2V5XG4gICAgY29uc3Qgc2lnbmluZ1NlY3JldCA9IG5ldyBzZWNyZXRzbWFuYWdlci5TZWNyZXQodGhpcywgXCJDVEFLZXlcIiwge1xuICAgICAgZ2VuZXJhdGVTZWNyZXRTdHJpbmc6IHtcbiAgICAgICAgc2VjcmV0U3RyaW5nVGVtcGxhdGU6ICd7XCJhbGdvcml0aG1cIjpcIkhNQUMtU0hBMjU2XCJ9JyxcbiAgICAgICAgZ2VuZXJhdGVTdHJpbmdLZXk6IFwic2lnbmluZ0tleVwiLFxuICAgICAgICBwYXNzd29yZExlbmd0aDogNjQsXG4gICAgICB9LFxuICAgICAgcmVtb3ZhbFBvbGljeTogUmVtb3ZhbFBvbGljeS5ERVNUUk9ZLFxuICAgIH0pO1xuXG4gICAgLy8gQ2xvdWRGcm9udCBLZXlWYWx1ZVN0b3JlIGZvciByZXZvY2F0aW9uXG4gICAgdGhpcy5rdlN0b3JlID0gbmV3IGNsb3VkZnJvbnQuS2V5VmFsdWVTdG9yZSh0aGlzLCBcIkNUQVJldm9jYXRpb25TdG9yZVwiLCB7XG4gICAgICBjb21tZW50OiBcIkNUQSB0b2tlbiByZXZvY2F0aW9uIGxpc3RcIixcbiAgICB9KTtcblxuICAgIC8vIENUQSB2YWxpZGF0b3IgZnVuY3Rpb25cbiAgICBjb25zdCB2YWxpZGF0b3IgPSBuZXcgY2xvdWRmcm9udC5GdW5jdGlvbih0aGlzLCBcIkNUQVZhbGlkYXRvclwiLCB7XG4gICAgICBjb2RlOiBjbG91ZGZyb250LkZ1bmN0aW9uQ29kZS5mcm9tRmlsZSh7IGZpbGVQYXRoOiBcImxhbWJkYS9jdGFfdG9rZW5fdmFsaWRhdG9yLmpzXCIgfSksXG4gICAgICBmdW5jdGlvbk5hbWU6IGAke0F3cy5TVEFDS19OQU1FfS1DVEEtVmFsaWRhdG9yYCxcbiAgICAgIHJ1bnRpbWU6IGNsb3VkZnJvbnQuRnVuY3Rpb25SdW50aW1lLkpTXzJfMCxcbiAgICAgIGtleVZhbHVlU3RvcmU6IHRoaXMua3ZTdG9yZSxcbiAgICB9KTtcblxuICAgIC8vIFRva2VuIGdlbmVyYXRvciAoTm9kZSBTREspXG4gICAgLy8gTm9kZWpzRnVuY3Rpb24gKGVzYnVpbGQpIGJ1bmRsZXMgdGhlIGhhbmRsZXIgdG9nZXRoZXIgd2l0aCBpdHNcbiAgICAvLyB0aGlyZC1wYXJ0eSBkZXBlbmRlbmN5IGNib3IteCwgd2hpY2ggaXMgTk9UIHByb3ZpZGVkIGJ5IHRoZSBMYW1iZGFcbiAgICAvLyBOb2RlLmpzIHJ1bnRpbWUuIEEgcGxhaW4gQ29kZS5mcm9tQXNzZXQoXCJsYW1iZGFcIikgc2hpcHMgbm8gbm9kZV9tb2R1bGVzLFxuICAgIC8vIHNvIHJlcXVpcmUoJ2Nib3IteCcpIGZhaWxzIGF0IG1vZHVsZSBpbml0IGFuZCBBUEkgR2F0ZXdheSByZXR1cm5zIGEgNTAyXG4gICAgLy8gd2l0aCBubyBDT1JTIGhlYWRlcnMg4oCUIHN1cmZhY2luZyBpbiB0aGUgYnJvd3NlciBhcyBhIENPUlMgZXJyb3IuXG4gICAgLy8gVGhlIEFXUyBTREsgdjMgcGFja2FnZXMgKEBhd3Mtc2RrLyopIHJlbWFpbiBleHRlcm5hbGl6ZWQgYnkgZGVmYXVsdFxuICAgIC8vIHNpbmNlIHRoZXkgQVJFIHByZXNlbnQgaW4gdGhlIHJ1bnRpbWUuXG4gICAgY29uc3QgZ2VuZXJhdG9yID0gbmV3IE5vZGVqc0Z1bmN0aW9uKHRoaXMsIFwiQ1RBR2VuZXJhdG9yXCIsIHtcbiAgICAgIHJ1bnRpbWU6IGxhbWJkYS5SdW50aW1lLk5PREVKU18yMl9YLFxuICAgICAgZW50cnk6IFwibGFtYmRhL2N0YV90b2tlbl9nZW5lcmF0b3IuanNcIixcbiAgICAgIGhhbmRsZXI6IFwiaGFuZGxlclwiLFxuICAgICAgdGltZW91dDogRHVyYXRpb24uc2Vjb25kcygxMCksXG4gICAgICBlbnZpcm9ubWVudDogeyBTRUNSRVRfTkFNRTogc2lnbmluZ1NlY3JldC5zZWNyZXROYW1lIH0sXG4gICAgfSk7XG5cbiAgICAvLyBUb2tlbiBnZW5lcmF0b3IgKFB5dGhvbiBTREspXG4gICAgY29uc3QgZ2VuZXJhdG9yUHl0aG9uID0gbmV3IGxhbWJkYS5GdW5jdGlvbih0aGlzLCBcIkNUQUdlbmVyYXRvclB5dGhvblwiLCB7XG4gICAgICBydW50aW1lOiBsYW1iZGEuUnVudGltZS5QWVRIT05fM18xMyxcbiAgICAgIGhhbmRsZXI6IFwiaGFuZGxlci5oYW5kbGVyXCIsXG4gICAgICBjb2RlOiBsYW1iZGEuQ29kZS5mcm9tQXNzZXQoXCJsYW1iZGEtcHl0aG9uXCIpLFxuICAgICAgdGltZW91dDogRHVyYXRpb24uc2Vjb25kcygxMCksXG4gICAgICBlbnZpcm9ubWVudDogeyBTRUNSRVRfTkFNRTogc2lnbmluZ1NlY3JldC5zZWNyZXROYW1lIH0sXG4gICAgfSk7XG5cbiAgICAvLyBUb2tlbiBnZW5lcmF0b3IgKFJ1YnkgU0RLKVxuICAgIGNvbnN0IGdlbmVyYXRvclJ1YnkgPSBuZXcgbGFtYmRhLkZ1bmN0aW9uKHRoaXMsIFwiQ1RBR2VuZXJhdG9yUnVieVwiLCB7XG4gICAgICBydW50aW1lOiBsYW1iZGEuUnVudGltZS5SVUJZXzNfMyxcbiAgICAgIGhhbmRsZXI6IFwiaGFuZGxlci5oYW5kbGVyXCIsXG4gICAgICBjb2RlOiBsYW1iZGEuQ29kZS5mcm9tQXNzZXQoXCJsYW1iZGEtcnVieVwiKSxcbiAgICAgIHRpbWVvdXQ6IER1cmF0aW9uLnNlY29uZHMoMTApLFxuICAgICAgZW52aXJvbm1lbnQ6IHsgU0VDUkVUX05BTUU6IHNpZ25pbmdTZWNyZXQuc2VjcmV0TmFtZSB9LFxuICAgIH0pO1xuXG4gICAgLy8gVG9rZW4gcmV2b2NhdGlvbiBoYW5kbGVyXG4gICAgY29uc3QgcmV2b2tlciA9IG5ldyBsYW1iZGEuRnVuY3Rpb24odGhpcywgXCJDVEFSZXZva2VyXCIsIHtcbiAgICAgIHJ1bnRpbWU6IGxhbWJkYS5SdW50aW1lLk5PREVKU18yMl9YLFxuICAgICAgaGFuZGxlcjogXCJjdGFfcmV2b2NhdGlvbi5oYW5kbGVyXCIsXG4gICAgICBjb2RlOiBsYW1iZGEuQ29kZS5mcm9tQXNzZXQoXCJsYW1iZGFcIiksXG4gICAgICB0aW1lb3V0OiBEdXJhdGlvbi5zZWNvbmRzKDEwKSxcbiAgICAgIGVudmlyb25tZW50OiB7IEtWU19BUk46IHRoaXMua3ZTdG9yZS5rZXlWYWx1ZVN0b3JlQXJuIH0sXG4gICAgfSk7XG5cbiAgICBzaWduaW5nU2VjcmV0LmdyYW50UmVhZChnZW5lcmF0b3IpO1xuICAgIHNpZ25pbmdTZWNyZXQuZ3JhbnRSZWFkKGdlbmVyYXRvclB5dGhvbik7XG4gICAgc2lnbmluZ1NlY3JldC5ncmFudFJlYWQoZ2VuZXJhdG9yUnVieSk7XG5cbiAgICAvLyBHcmFudCBLVlMgdXBkYXRlIHBlcm1pc3Npb24gdmlhIElBTSBwb2xpY3lcbiAgICByZXZva2VyLmFkZFRvUm9sZVBvbGljeShuZXcgaWFtLlBvbGljeVN0YXRlbWVudCh7XG4gICAgICBlZmZlY3Q6IGlhbS5FZmZlY3QuQUxMT1csXG4gICAgICBhY3Rpb25zOiBbXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6UHV0S2V5XCIsIFwiY2xvdWRmcm9udC1rZXl2YWx1ZXN0b3JlOkRlc2NyaWJlS2V5VmFsdWVTdG9yZVwiXSxcbiAgICAgIHJlc291cmNlczogW3RoaXMua3ZTdG9yZS5rZXlWYWx1ZVN0b3JlQXJuXSxcbiAgICB9KSk7XG5cbiAgICAvLyAtLS0gS2V5IHN5bmMgTGFtYmRhIChjdXN0b20gcmVzb3VyY2UgKyByb3RhdGlvbikgLS0tXG4gICAgY29uc3Qgc3luY0tleXNUb0t2cyA9IG5ldyBsYW1iZGEuRnVuY3Rpb24odGhpcywgXCJTeW5jS2V5c1RvS3ZzXCIsIHtcbiAgICAgIHJ1bnRpbWU6IGxhbWJkYS5SdW50aW1lLk5PREVKU18yMl9YLFxuICAgICAgaGFuZGxlcjogXCJpbmRleC5oYW5kbGVyXCIsXG4gICAgICBjb2RlOiBsYW1iZGEuQ29kZS5mcm9tQXNzZXQoXCJsYW1iZGEvc3luY19rZXlzXCIpLFxuICAgICAgdGltZW91dDogRHVyYXRpb24uc2Vjb25kcygzMCksXG4gICAgICBlbnZpcm9ubWVudDoge1xuICAgICAgICBTRUNSRVRfTkFNRTogc2lnbmluZ1NlY3JldC5zZWNyZXROYW1lLFxuICAgICAgICBLVlNfQVJOOiB0aGlzLmt2U3RvcmUua2V5VmFsdWVTdG9yZUFybixcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICBzaWduaW5nU2VjcmV0LmdyYW50UmVhZChzeW5jS2V5c1RvS3ZzKTtcbiAgICBzaWduaW5nU2VjcmV0LmdyYW50V3JpdGUoc3luY0tleXNUb0t2cyk7XG4gICAgc3luY0tleXNUb0t2cy5hZGRUb1JvbGVQb2xpY3kobmV3IGlhbS5Qb2xpY3lTdGF0ZW1lbnQoe1xuICAgICAgZWZmZWN0OiBpYW0uRWZmZWN0LkFMTE9XLFxuICAgICAgYWN0aW9uczogW1xuICAgICAgICBcImNsb3VkZnJvbnQta2V5dmFsdWVzdG9yZTpQdXRLZXlcIixcbiAgICAgICAgXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6RGVzY3JpYmVLZXlWYWx1ZVN0b3JlXCIsXG4gICAgICBdLFxuICAgICAgcmVzb3VyY2VzOiBbdGhpcy5rdlN0b3JlLmtleVZhbHVlU3RvcmVBcm5dLFxuICAgIH0pKTtcblxuICAgIC8vIEN1c3RvbSByZXNvdXJjZTogc3luYyBrZXkgdG8gS1ZTIG9uIGRlcGxveVxuICAgIGNvbnN0IGtleVN5bmNQcm92aWRlciA9IG5ldyBjdXN0b21fcmVzb3VyY2VzLlByb3ZpZGVyKHRoaXMsIFwiS2V5U3luY1Byb3ZpZGVyXCIsIHtcbiAgICAgIG9uRXZlbnRIYW5kbGVyOiBzeW5jS2V5c1RvS3ZzLFxuICAgIH0pO1xuXG4gICAgbmV3IEN1c3RvbVJlc291cmNlKHRoaXMsIFwiS2V5U3luY1Jlc291cmNlXCIsIHtcbiAgICAgIHNlcnZpY2VUb2tlbjoga2V5U3luY1Byb3ZpZGVyLnNlcnZpY2VUb2tlbixcbiAgICAgIHByb3BlcnRpZXM6IHtcbiAgICAgICAgLy8gRm9yY2UgdXBkYXRlIG9uIGVhY2ggZGVwbG95IHRvIGVuc3VyZSBrZXkgaXMgc3luY2VkXG4gICAgICAgIFRpbWVzdGFtcDogRGF0ZS5ub3coKS50b1N0cmluZygpLFxuICAgICAgfSxcbiAgICB9KTtcblxuICAgIC8vIC0tLSBLZXkgcm90YXRpb24gd29ya2Zsb3cgLS0tXG4gICAgY29uc3Qgcm90YXRlS2V5VGFzayA9IG5ldyB0YXNrcy5MYW1iZGFJbnZva2UodGhpcywgXCJSb3RhdGVTaWduaW5nS2V5XCIsIHtcbiAgICAgIGxhbWJkYUZ1bmN0aW9uOiBzeW5jS2V5c1RvS3ZzLFxuICAgICAgcGF5bG9hZDogc2ZuLlRhc2tJbnB1dC5mcm9tT2JqZWN0KHsgcm90YXRlOiB0cnVlIH0pLFxuICAgICAgcmVzdWx0UGF0aDogc2ZuLkpzb25QYXRoLkRJU0NBUkQsXG4gICAgfSk7XG5cbiAgICBjb25zdCByb3RhdGlvbldvcmtmbG93ID0gbmV3IHNmbi5TdGF0ZU1hY2hpbmUodGhpcywgXCJLZXlSb3RhdGlvbldvcmtmbG93XCIsIHtcbiAgICAgIHN0YXRlTWFjaGluZU5hbWU6IGAke0F3cy5TVEFDS19OQU1FfV9Sb3RhdGVLZXlzYCxcbiAgICAgIGRlZmluaXRpb25Cb2R5OiBzZm4uRGVmaW5pdGlvbkJvZHkuZnJvbUNoYWluYWJsZShyb3RhdGVLZXlUYXNrKSxcbiAgICAgIHRpbWVvdXQ6IER1cmF0aW9uLm1pbnV0ZXMoNSksXG4gICAgfSk7XG5cbiAgICAvLyBSb3RhdGUga2V5cyBtb250aGx5IGJ5IGRlZmF1bHRcbiAgICBjb25zdCByb3RhdGlvblNjaGVkdWxlID0gY29uZmlnLm1haW4ucm90YXRpb25GcmVxdWVuY3kgfHwgXCIzMGRcIjtcbiAgICBjb25zdCByb3RhdGlvblJhdGUgPSB0aGlzLnBhcnNlUm90YXRpb25SYXRlKHJvdGF0aW9uU2NoZWR1bGUpO1xuICAgIG5ldyBldmVudHMuUnVsZSh0aGlzLCBcIktleVJvdGF0aW9uU2NoZWR1bGVcIiwge1xuICAgICAgc2NoZWR1bGU6IGV2ZW50cy5TY2hlZHVsZS5yYXRlKHJvdGF0aW9uUmF0ZSksXG4gICAgICB0YXJnZXRzOiBbbmV3IHRhcmdldHMuU2ZuU3RhdGVNYWNoaW5lKHJvdGF0aW9uV29ya2Zsb3cpXSxcbiAgICB9KTtcblxuICAgIC8vIEFQSSBHYXRld2F5XG4gICAgY29uc3QgYXBpID0gbmV3IGFwaWdhdGV3YXkuUmVzdEFwaSh0aGlzLCBcIkNUQUFQSVwiLCB7XG4gICAgICByZXN0QXBpTmFtZTogXCJDVEEgVG9rZW4gQVBJXCIsXG4gICAgICBkZWZhdWx0Q29yc1ByZWZsaWdodE9wdGlvbnM6IHtcbiAgICAgICAgYWxsb3dPcmlnaW5zOiBhcGlnYXRld2F5LkNvcnMuQUxMX09SSUdJTlMsXG4gICAgICAgIGFsbG93TWV0aG9kczogYXBpZ2F0ZXdheS5Db3JzLkFMTF9NRVRIT0RTLFxuICAgICAgfSxcbiAgICB9KTtcblxuICAgIGNvbnN0IHRva2VuUmVzb3VyY2UgPSBhcGkucm9vdC5hZGRSZXNvdXJjZShcInRva2VuXCIpO1xuICAgIHRva2VuUmVzb3VyY2UuYWRkTWV0aG9kKFwiUE9TVFwiLCBuZXcgYXBpZ2F0ZXdheS5MYW1iZGFJbnRlZ3JhdGlvbihnZW5lcmF0b3IpKTtcblxuICAgIGNvbnN0IHRva2VuUHl0aG9uUmVzb3VyY2UgPSBhcGkucm9vdC5hZGRSZXNvdXJjZShcInRva2VuLXB5dGhvblwiKTtcbiAgICB0b2tlblB5dGhvblJlc291cmNlLmFkZE1ldGhvZChcIlBPU1RcIiwgbmV3IGFwaWdhdGV3YXkuTGFtYmRhSW50ZWdyYXRpb24oZ2VuZXJhdG9yUHl0aG9uKSk7XG5cbiAgICBjb25zdCB0b2tlblJ1YnlSZXNvdXJjZSA9IGFwaS5yb290LmFkZFJlc291cmNlKFwidG9rZW4tcnVieVwiKTtcbiAgICB0b2tlblJ1YnlSZXNvdXJjZS5hZGRNZXRob2QoXCJQT1NUXCIsIG5ldyBhcGlnYXRld2F5LkxhbWJkYUludGVncmF0aW9uKGdlbmVyYXRvclJ1YnkpKTtcbiAgICBcbiAgICBjb25zdCByZXZva2VSZXNvdXJjZSA9IGFwaS5yb290LmFkZFJlc291cmNlKFwicmV2b2tlXCIpO1xuICAgIHJldm9rZVJlc291cmNlLmFkZE1ldGhvZChcIlBPU1RcIiwgbmV3IGFwaWdhdGV3YXkuTGFtYmRhSW50ZWdyYXRpb24ocmV2b2tlcikpO1xuXG4gICAgLy8gRGVtbyB3ZWJzaXRlIChjb25kaXRpb25hbClcbiAgICBsZXQgZGlzdHJpYnV0aW9uOiBjbG91ZGZyb250LkRpc3RyaWJ1dGlvbjtcbiAgICBsZXQgZGVtb0J1Y2tldDogczMuQnVja2V0IHwgdW5kZWZpbmVkO1xuICAgIFxuICAgIGlmIChjb25maWcubWFpbi5lbmFibGVEZW1vKSB7XG4gICAgICBkZW1vQnVja2V0ID0gbmV3IHMzLkJ1Y2tldCh0aGlzLCBcIkRlbW9XZWJzaXRlXCIsIHtcbiAgICAgICAgcmVtb3ZhbFBvbGljeTogUmVtb3ZhbFBvbGljeS5ERVNUUk9ZLFxuICAgICAgICBhdXRvRGVsZXRlT2JqZWN0czogdHJ1ZSxcbiAgICAgIH0pO1xuXG4gICAgICBuZXcgczNkZXBsb3kuQnVja2V0RGVwbG95bWVudCh0aGlzLCBcIkRlcGxveURlbW9TaXRlXCIsIHtcbiAgICAgICAgc291cmNlczogW3MzZGVwbG95LlNvdXJjZS5hc3NldChcInJlc291cmNlcy9kZW1vLXdlYnNpdGVcIildLFxuICAgICAgICBkZXN0aW5hdGlvbkJ1Y2tldDogZGVtb0J1Y2tldCxcbiAgICAgICAgZGVzdGluYXRpb25LZXlQcmVmaXg6IFwid2Vic2l0ZVwiLFxuICAgICAgICBwcnVuZTogZmFsc2UsXG4gICAgICB9KTtcblxuICAgICAgZGlzdHJpYnV0aW9uID0gbmV3IGNsb3VkZnJvbnQuRGlzdHJpYnV0aW9uKHRoaXMsIFwiQ1RBRGlzdHJpYnV0aW9uXCIsIHtcbiAgICAgICAgZGVmYXVsdEJlaGF2aW9yOiB7XG4gICAgICAgICAgb3JpZ2luOiBuZXcgSHR0cE9yaWdpbihcImNkbi5tZWRpYXBsYXlwZW4uY29tXCIpLFxuICAgICAgICAgIHZpZXdlclByb3RvY29sUG9saWN5OiBjbG91ZGZyb250LlZpZXdlclByb3RvY29sUG9saWN5LlJFRElSRUNUX1RPX0hUVFBTLFxuICAgICAgICAgIGNhY2hlUG9saWN5OiBuZXcgY2xvdWRmcm9udC5DYWNoZVBvbGljeSh0aGlzLCBcIkNUQUNhY2hlUG9saWN5XCIsIHtcbiAgICAgICAgICAgIGhlYWRlckJlaGF2aW9yOiBjbG91ZGZyb250LkNhY2hlSGVhZGVyQmVoYXZpb3IuYWxsb3dMaXN0KFxuICAgICAgICAgICAgICBcIkNsb3VkRnJvbnQtVmlld2VyLUNvdW50cnlcIlxuICAgICAgICAgICAgKSxcbiAgICAgICAgICB9KSxcbiAgICAgICAgICBvcmlnaW5SZXF1ZXN0UG9saWN5OiBjbG91ZGZyb250Lk9yaWdpblJlcXVlc3RQb2xpY3kuQUxMX1ZJRVdFUl9FWENFUFRfSE9TVF9IRUFERVIsXG4gICAgICAgICAgZnVuY3Rpb25Bc3NvY2lhdGlvbnM6IFt7XG4gICAgICAgICAgICBmdW5jdGlvbjogdmFsaWRhdG9yLFxuICAgICAgICAgICAgZXZlbnRUeXBlOiBjbG91ZGZyb250LkZ1bmN0aW9uRXZlbnRUeXBlLlZJRVdFUl9SRVFVRVNULFxuICAgICAgICAgIH1dLFxuICAgICAgICB9LFxuICAgICAgICBhZGRpdGlvbmFsQmVoYXZpb3JzOiB7XG4gICAgICAgICAgXCIvYXBpLypcIjoge1xuICAgICAgICAgICAgb3JpZ2luOiBuZXcgUmVzdEFwaU9yaWdpbihhcGkpLFxuICAgICAgICAgICAgdmlld2VyUHJvdG9jb2xQb2xpY3k6IGNsb3VkZnJvbnQuVmlld2VyUHJvdG9jb2xQb2xpY3kuUkVESVJFQ1RfVE9fSFRUUFMsXG4gICAgICAgICAgICBhbGxvd2VkTWV0aG9kczogY2xvdWRmcm9udC5BbGxvd2VkTWV0aG9kcy5BTExPV19BTEwsXG4gICAgICAgICAgICBjYWNoZVBvbGljeTogY2xvdWRmcm9udC5DYWNoZVBvbGljeS5DQUNISU5HX0RJU0FCTEVELFxuICAgICAgICAgICAgb3JpZ2luUmVxdWVzdFBvbGljeTogY2xvdWRmcm9udC5PcmlnaW5SZXF1ZXN0UG9saWN5LkFMTF9WSUVXRVJfRVhDRVBUX0hPU1RfSEVBREVSLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCIvd2Vic2l0ZS8qXCI6IHtcbiAgICAgICAgICAgIG9yaWdpbjogUzNCdWNrZXRPcmlnaW4ud2l0aE9yaWdpbkFjY2Vzc0NvbnRyb2woZGVtb0J1Y2tldCksXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuXG4gICAgfSBlbHNlIHtcbiAgICAgIGRpc3RyaWJ1dGlvbiA9IG5ldyBjbG91ZGZyb250LkRpc3RyaWJ1dGlvbih0aGlzLCBcIkNUQURpc3RyaWJ1dGlvblwiLCB7XG4gICAgICAgIGRlZmF1bHRCZWhhdmlvcjoge1xuICAgICAgICAgIG9yaWdpbjogbmV3IFJlc3RBcGlPcmlnaW4oYXBpKSxcbiAgICAgICAgICBmdW5jdGlvbkFzc29jaWF0aW9uczogW3tcbiAgICAgICAgICAgIGZ1bmN0aW9uOiB2YWxpZGF0b3IsXG4gICAgICAgICAgICBldmVudFR5cGU6IGNsb3VkZnJvbnQuRnVuY3Rpb25FdmVudFR5cGUuVklFV0VSX1JFUVVFU1QsXG4gICAgICAgICAgfV0sXG4gICAgICAgIH0sXG4gICAgICB9KTtcbiAgICB9XG5cbiAgICB0aGlzLmRpc3RyaWJ1dGlvbiA9IGRpc3RyaWJ1dGlvbjtcbiAgICBpZiAoY29uZmlnLm1haW4uZW5hYmxlRGVtbykge1xuICAgICAgdGhpcy5kZW1vQnVja2V0ID0gZGVtb0J1Y2tldCE7XG4gICAgfVxuXG4gICAgLy8gLS0tIFJlYWwtVGltZSBMb2dnaW5nIHZpYSBLaW5lc2lzIC0tLVxuICAgIGNvbnN0IGxvZ1N0cmVhbSA9IG5ldyBraW5lc2lzLlN0cmVhbSh0aGlzLCBcIlJlYWx0aW1lTG9nU3RyZWFtXCIsIHtcbiAgICAgIHN0cmVhbU1vZGU6IGtpbmVzaXMuU3RyZWFtTW9kZS5PTl9ERU1BTkQsXG4gICAgICByZXRlbnRpb25QZXJpb2Q6IER1cmF0aW9uLmhvdXJzKDI0KSxcbiAgICB9KTtcbiAgICB0aGlzLmxvZ1N0cmVhbSA9IGxvZ1N0cmVhbTtcblxuICAgIGNvbnN0IGNmS2luZXNpc1JvbGUgPSBuZXcgaWFtLlJvbGUodGhpcywgXCJDbG91ZEZyb250S2luZXNpc1JvbGVcIiwge1xuICAgICAgYXNzdW1lZEJ5OiBuZXcgaWFtLlNlcnZpY2VQcmluY2lwYWwoXCJjbG91ZGZyb250LmFtYXpvbmF3cy5jb21cIiksXG4gICAgfSk7XG4gICAgbG9nU3RyZWFtLmdyYW50V3JpdGUoY2ZLaW5lc2lzUm9sZSk7XG5cbiAgICBjb25zdCByZWFsdGltZUxvZ0NvbmZpZyA9IG5ldyBjbG91ZGZyb250LkNmblJlYWx0aW1lTG9nQ29uZmlnKHRoaXMsIFwiUmVhbHRpbWVMb2dDb25maWdcIiwge1xuICAgICAgbmFtZTogYCR7QXdzLlNUQUNLX05BTUV9LXJlYWx0aW1lLWxvZ3NgLFxuICAgICAgc2FtcGxpbmdSYXRlOiAxMDAsXG4gICAgICBlbmRQb2ludHM6IFt7XG4gICAgICAgIHN0cmVhbVR5cGU6IFwiS2luZXNpc1wiLFxuICAgICAgICBraW5lc2lzU3RyZWFtQ29uZmlnOiB7XG4gICAgICAgICAgcm9sZUFybjogY2ZLaW5lc2lzUm9sZS5yb2xlQXJuLFxuICAgICAgICAgIHN0cmVhbUFybjogbG9nU3RyZWFtLnN0cmVhbUFybixcbiAgICAgICAgfSxcbiAgICAgIH1dLFxuICAgICAgZmllbGRzOiBbXG4gICAgICAgIFwidGltZXN0YW1wXCIsIFwiYy1pcFwiLCBcInNjLXN0YXR1c1wiLCBcImNzLXVyaS1zdGVtXCIsIFwiY3MtbWV0aG9kXCIsXG4gICAgICAgIFwiY3MtaG9zdFwiLCBcImNzLXVzZXItYWdlbnRcIiwgXCJzYy1ieXRlc1wiLCBcInRpbWUtdGFrZW5cIiwgXCJjLWNvdW50cnlcIixcbiAgICAgIF0sXG4gICAgfSk7XG5cbiAgICAvLyBBdHRhY2ggcmVhbC10aW1lIGxvZ3MgdG8gdGhlIGRlZmF1bHQgY2FjaGUgYmVoYXZpb3JcbiAgICBjb25zdCBjZm5EaXN0ID0gZGlzdHJpYnV0aW9uLm5vZGUuZGVmYXVsdENoaWxkIGFzIGNsb3VkZnJvbnQuQ2ZuRGlzdHJpYnV0aW9uO1xuICAgIGNmbkRpc3QuYWRkUHJvcGVydHlPdmVycmlkZShcbiAgICAgIFwiRGlzdHJpYnV0aW9uQ29uZmlnLkRlZmF1bHRDYWNoZUJlaGF2aW9yLlJlYWx0aW1lTG9nQ29uZmlnQXJuXCIsXG4gICAgICByZWFsdGltZUxvZ0NvbmZpZy5hdHRyQXJuXG4gICAgKTtcblxuICAgIC8vIC0tLSBEYXNoYm9hcmQ6IGxpc3QgcmV2b2tlZCBzZXNzaW9ucyBmcm9tIEtWUyAtLS1cbiAgICBjb25zdCBsaXN0UmV2b2tlZCA9IG5ldyBsYW1iZGEuRnVuY3Rpb24odGhpcywgXCJMaXN0UmV2b2tlZFwiLCB7XG4gICAgICBydW50aW1lOiBsYW1iZGEuUnVudGltZS5OT0RFSlNfMjJfWCxcbiAgICAgIGhhbmRsZXI6IFwibGlzdF9yZXZva2VkLmhhbmRsZXJcIixcbiAgICAgIGNvZGU6IGxhbWJkYS5Db2RlLmZyb21Bc3NldChcImxhbWJkYVwiKSxcbiAgICAgIHRpbWVvdXQ6IER1cmF0aW9uLnNlY29uZHMoMTApLFxuICAgICAgZW52aXJvbm1lbnQ6IHsgS1ZTX0FSTjogdGhpcy5rdlN0b3JlLmtleVZhbHVlU3RvcmVBcm4gfSxcbiAgICB9KTtcbiAgICBsaXN0UmV2b2tlZC5hZGRUb1JvbGVQb2xpY3kobmV3IGlhbS5Qb2xpY3lTdGF0ZW1lbnQoe1xuICAgICAgYWN0aW9uczogW1wiY2xvdWRmcm9udC1rZXl2YWx1ZXN0b3JlOkxpc3RLZXlzXCIsIFwiY2xvdWRmcm9udC1rZXl2YWx1ZXN0b3JlOkRlc2NyaWJlS2V5VmFsdWVTdG9yZVwiXSxcbiAgICAgIHJlc291cmNlczogW3RoaXMua3ZTdG9yZS5rZXlWYWx1ZVN0b3JlQXJuXSxcbiAgICB9KSk7XG5cbiAgICAvLyBBZGQgL3Jldm9rZWQgdG8gdGhlIGV4aXN0aW5nIEFQSVxuICAgIGFwaS5yb290LmFkZFJlc291cmNlKFwicmV2b2tlZFwiKS5hZGRNZXRob2QoXCJHRVRcIixcbiAgICAgIG5ldyBhcGlnYXRld2F5LkxhbWJkYUludGVncmF0aW9uKGxpc3RSZXZva2VkKVxuICAgICk7XG5cbiAgICAvLyBEZXBsb3kgZGFzaGJvYXJkIEhUTUwgKGFsb25nc2lkZSBkZW1vIHNpdGUgaWYgZW5hYmxlZClcbiAgICBpZiAoY29uZmlnLm1haW4uZW5hYmxlRGVtbykge1xuICAgICAgbmV3IHMzZGVwbG95LkJ1Y2tldERlcGxveW1lbnQodGhpcywgXCJEZXBsb3lEYXNoYm9hcmRcIiwge1xuICAgICAgICBzb3VyY2VzOiBbXG4gICAgICAgICAgczNkZXBsb3kuU291cmNlLmFzc2V0KFwicmVzb3VyY2VzL2Rhc2hib2FyZFwiKSxcbiAgICAgICAgICBzM2RlcGxveS5Tb3VyY2UuZGF0YShcImNvbmZpZy5qc1wiLFxuICAgICAgICAgICAgYHdpbmRvdy5DVEFfQ09ORklHPXthcGlFbmRwb2ludDpcIiR7YXBpLnVybC5yZXBsYWNlKC9cXC8kLywnJyl9XCIsY2RuRG9tYWluOlwiaHR0cHM6Ly8ke2Rpc3RyaWJ1dGlvbi5kaXN0cmlidXRpb25Eb21haW5OYW1lfVwifTtgXG4gICAgICAgICAgKSxcbiAgICAgICAgXSxcbiAgICAgICAgZGVzdGluYXRpb25CdWNrZXQ6IGRlbW9CdWNrZXQhLFxuICAgICAgICBkZXN0aW5hdGlvbktleVByZWZpeDogXCJ3ZWJzaXRlXCIsXG4gICAgICAgIHBydW5lOiBmYWxzZSxcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIC8vIC0tLSBLVlMgQ2xlYW51cDogcHVyZ2UgZXhwaXJlZCByZXZvY2F0aW9ucyBvbiBhIHNjaGVkdWxlIC0tLVxuICAgIGNvbnN0IGt2c0NsZWFudXAgPSBuZXcgbGFtYmRhLkZ1bmN0aW9uKHRoaXMsIFwiS3ZzQ2xlYW51cFwiLCB7XG4gICAgICBydW50aW1lOiBsYW1iZGEuUnVudGltZS5OT0RFSlNfMjJfWCxcbiAgICAgIGhhbmRsZXI6IFwia3ZzX2NsZWFudXAuaGFuZGxlclwiLFxuICAgICAgY29kZTogbGFtYmRhLkNvZGUuZnJvbUFzc2V0KFwibGFtYmRhXCIpLFxuICAgICAgdGltZW91dDogRHVyYXRpb24ubWludXRlcygyKSxcbiAgICAgIGVudmlyb25tZW50OiB7IEtWU19BUk46IHRoaXMua3ZTdG9yZS5rZXlWYWx1ZVN0b3JlQXJuLCBUVExfSE9VUlM6IFwiMjRcIiB9LFxuICAgIH0pO1xuICAgIGt2c0NsZWFudXAuYWRkVG9Sb2xlUG9saWN5KG5ldyBpYW0uUG9saWN5U3RhdGVtZW50KHtcbiAgICAgIGFjdGlvbnM6IFtcImNsb3VkZnJvbnQta2V5dmFsdWVzdG9yZTpMaXN0S2V5c1wiLCBcImNsb3VkZnJvbnQta2V5dmFsdWVzdG9yZTpEZWxldGVLZXlcIiwgXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6RGVzY3JpYmVLZXlWYWx1ZVN0b3JlXCJdLFxuICAgICAgcmVzb3VyY2VzOiBbdGhpcy5rdlN0b3JlLmtleVZhbHVlU3RvcmVBcm5dLFxuICAgIH0pKTtcbiAgICBuZXcgZXZlbnRzLlJ1bGUodGhpcywgXCJLdnNDbGVhbnVwU2NoZWR1bGVcIiwge1xuICAgICAgc2NoZWR1bGU6IGV2ZW50cy5TY2hlZHVsZS5yYXRlKER1cmF0aW9uLmhvdXJzKDEpKSxcbiAgICAgIHRhcmdldHM6IFtuZXcgdGFyZ2V0cy5MYW1iZGFGdW5jdGlvbihrdnNDbGVhbnVwKV0sXG4gICAgfSk7XG5cbiAgICAvLyBPdXRwdXRzXG4gICAgbmV3IENmbk91dHB1dCh0aGlzLCBcIkFQSUVuZHBvaW50XCIsIHsgXG4gICAgICB2YWx1ZTogYGh0dHBzOi8vJHtkaXN0cmlidXRpb24uZGlzdHJpYnV0aW9uRG9tYWluTmFtZX0vYXBpYCxcbiAgICAgIGRlc2NyaXB0aW9uOiBcIkNUQSBBUEkgRW5kcG9pbnRcIlxuICAgIH0pO1xuICAgIFxuICAgIGlmIChjb25maWcubWFpbi5lbmFibGVEZW1vKSB7XG4gICAgICBuZXcgQ2ZuT3V0cHV0KHRoaXMsIFwiRGVtb1dlYnNpdGVVcmxcIiwgeyBcbiAgICAgICAgdmFsdWU6IGBodHRwczovLyR7ZGlzdHJpYnV0aW9uLmRpc3RyaWJ1dGlvbkRvbWFpbk5hbWV9L3dlYnNpdGUvaW5kZXguaHRtbGAsXG4gICAgICAgIGRlc2NyaXB0aW9uOiBcIkNUQSBEZW1vIFdlYnNpdGUgVVJMXCJcbiAgICAgIH0pO1xuICAgIH1cbiAgICBcbiAgICBuZXcgQ2ZuT3V0cHV0KHRoaXMsIFwiS2V5VmFsdWVTdG9yZUlkXCIsIHsgXG4gICAgICB2YWx1ZTogdGhpcy5rdlN0b3JlLmtleVZhbHVlU3RvcmVJZCxcbiAgICAgIGRlc2NyaXB0aW9uOiBcIkNsb3VkRnJvbnQgS2V5VmFsdWVTdG9yZSBJRFwiXG4gICAgfSk7XG5cbiAgICBuZXcgQ2ZuT3V0cHV0KHRoaXMsIFwiU2VjcmV0QXJuXCIsIHtcbiAgICAgIHZhbHVlOiBzaWduaW5nU2VjcmV0LnNlY3JldEFybixcbiAgICAgIGRlc2NyaXB0aW9uOiBcIkNUQSBzaWduaW5nIHNlY3JldCBBUk5cIlxuICAgIH0pO1xuXG4gICAgbmV3IENmbk91dHB1dCh0aGlzLCBcIkNUQVN0YW5kYXJkXCIsIHtcbiAgICAgIHZhbHVlOiBcIkNUQS01MDA3LUJcIixcbiAgICAgIGRlc2NyaXB0aW9uOiBcIkltcGxlbWVudGVkIHN0YW5kYXJkIHZlcnNpb25cIlxuICAgIH0pO1xuXG4gICAgbmV3IENmbk91dHB1dCh0aGlzLCBcIlJvdGF0aW9uV29ya2Zsb3dcIiwge1xuICAgICAgdmFsdWU6IHJvdGF0aW9uV29ya2Zsb3cuc3RhdGVNYWNoaW5lTmFtZSxcbiAgICAgIGRlc2NyaXB0aW9uOiBcIktleSByb3RhdGlvbiBTdGVwIEZ1bmN0aW9ucyB3b3JrZmxvd1wiXG4gICAgfSk7XG4gIH1cblxuICBwcml2YXRlIHBhcnNlUm90YXRpb25SYXRlKHJhdGU6IHN0cmluZyk6IER1cmF0aW9uIHtcbiAgICBjb25zdCBtYXRjaCA9IHJhdGUubWF0Y2goL14oXFxkKykoW21oZF0pJC8pO1xuICAgIGlmICghbWF0Y2gpIHJldHVybiBEdXJhdGlvbi5kYXlzKDMwKTtcbiAgICBjb25zdCB2YWx1ZSA9IHBhcnNlSW50KG1hdGNoWzFdKTtcbiAgICBzd2l0Y2ggKG1hdGNoWzJdKSB7XG4gICAgICBjYXNlICdtJzogcmV0dXJuIER1cmF0aW9uLm1pbnV0ZXModmFsdWUpO1xuICAgICAgY2FzZSAnaCc6IHJldHVybiBEdXJhdGlvbi5ob3Vycyh2YWx1ZSk7XG4gICAgICBjYXNlICdkJzogcmV0dXJuIER1cmF0aW9uLmRheXModmFsdWUpO1xuICAgICAgZGVmYXVsdDogcmV0dXJuIER1cmF0aW9uLmRheXMoMzApO1xuICAgIH1cbiAgfVxufVxuIl19