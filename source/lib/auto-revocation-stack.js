"use strict";
/**
 * CTA Auto-Revocation Stack (optional)
 *
 * Adds AI-powered session analysis to the real-time log pipeline.
 * Consumes the Kinesis stream created by the main stack, analyzes
 * session patterns with Bedrock Nova Pro, and revokes suspicious
 * sessions in CloudFront KeyValueStore.
 *
 * The main stack handles: Kinesis stream, RealtimeLogConfig, dashboard.
 * This stack adds: Lambda consumer + Bedrock analysis.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.AutoRevocationStack = void 0;
const aws_cdk_lib_1 = require("aws-cdk-lib");
class AutoRevocationStack extends aws_cdk_lib_1.Stack {
    constructor(scope, id, props) {
        super(scope, id, props);
        const config = props.config;
        const bedrockRegion = config.bedrock?.region || this.region;
        const bedrockModel = config.bedrock?.model || "amazon.nova-lite-v1:0";
        // Kinesis stream processor — aggregates sessions, calls Bedrock, revokes
        const analyzer = new aws_cdk_lib_1.aws_lambda.Function(this, "KinesisAnalyzer", {
            runtime: aws_cdk_lib_1.aws_lambda.Runtime.NODEJS_22_X,
            handler: "kinesis_analyzer.handler",
            code: aws_cdk_lib_1.aws_lambda.Code.fromAsset("lambda"),
            timeout: aws_cdk_lib_1.Duration.minutes(5),
            memorySize: 512,
            environment: {
                KVS_ARN: props.kvStore.keyValueStoreArn,
                BEDROCK_REGION: bedrockRegion,
                BEDROCK_MODEL: bedrockModel,
            },
        });
        // Consume the Kinesis stream from the main stack
        analyzer.addEventSource(new aws_cdk_lib_1.aws_lambda_event_sources.KinesisEventSource(props.logStream, {
            startingPosition: aws_cdk_lib_1.aws_lambda.StartingPosition.LATEST,
            batchSize: 500,
            maxBatchingWindow: aws_cdk_lib_1.Duration.seconds(60),
            retryAttempts: 2,
        }));
        // Bedrock permissions
        analyzer.addToRolePolicy(new aws_cdk_lib_1.aws_iam.PolicyStatement({
            actions: ["bedrock:InvokeModel"],
            resources: [`arn:aws:bedrock:${bedrockRegion}::foundation-model/${bedrockModel}`],
        }));
        // KVS permissions for writing revocations
        analyzer.addToRolePolicy(new aws_cdk_lib_1.aws_iam.PolicyStatement({
            actions: ["cloudfront-keyvaluestore:PutKey", "cloudfront-keyvaluestore:DescribeKeyValueStore"],
            resources: [props.kvStore.keyValueStoreArn],
        }));
        // --- Editable Bedrock Prompt via SSM Parameter Store ---
        const promptParam = new aws_cdk_lib_1.aws_ssm.StringParameter(this, "BedrockPrompt", {
            parameterName: `/${this.stackName}/bedrock-prompt`,
            stringValue: "You are a video streaming security analyst. Analyze these CTA-5007-B token session metrics from CloudFront real-time logs and identify sessions that should be revoked due to unauthorized sharing or abuse.\n\nEach session represents a unique CTA token being used to access protected video content through CloudFront.\n\n## Indicators of Token Sharing / Abuse\n- Multiple distinct IP addresses using the same token (strongest signal)\n- Requests from multiple countries with the same token\n- Multiple different User-Agent strings (different devices/browsers)\n- Abnormally high request rates (automated scraping)\n- High error rates combined with high request volume (brute force)\n\n## Indicators of Legitimate Use\n- Single IP, single country, single User-Agent = normal viewer\n- Moderate request rates (1-5 requests/sec is normal for adaptive streaming)\n- IP changes within the same country could be mobile network handoff (less suspicious)\n\n## Instructions\nRespond with ONLY a JSON array of session keys that should be revoked. If no sessions should be revoked, respond with an empty array [].\nBe conservative — only revoke sessions with strong evidence of sharing or abuse.",
        });
        // Pass SSM param name to the analyzer Lambda
        analyzer.addEnvironment("PROMPT_PARAM", promptParam.parameterName);
        promptParam.grantRead(analyzer);
        // Prompt management API
        const promptManager = new aws_cdk_lib_1.aws_lambda.Function(this, "PromptManager", {
            runtime: aws_cdk_lib_1.aws_lambda.Runtime.NODEJS_22_X,
            handler: "prompt_manager.handler",
            code: aws_cdk_lib_1.aws_lambda.Code.fromAsset("lambda"),
            timeout: aws_cdk_lib_1.Duration.seconds(10),
            environment: { PROMPT_PARAM: promptParam.parameterName },
        });
        promptParam.grantRead(promptManager);
        promptParam.grantWrite(promptManager);
        const promptApi = new aws_cdk_lib_1.aws_apigateway.RestApi(this, "PromptAPI", {
            restApiName: "CTA Prompt API",
            defaultCorsPreflightOptions: {
                allowOrigins: aws_cdk_lib_1.aws_apigateway.Cors.ALL_ORIGINS,
                allowMethods: aws_cdk_lib_1.aws_apigateway.Cors.ALL_METHODS,
            },
        });
        // Attach CORS headers to default gateway responses so integration errors
        // (Lambda 5xx/timeout, or a 4xx) still carry Access-Control-Allow-Origin
        // instead of surfacing in the browser as a misleading CORS error.
        const corsResponseHeaders = {
            "Access-Control-Allow-Origin": "'*'",
            "Access-Control-Allow-Headers": "'*'",
        };
        promptApi.addGatewayResponse("Default4XX", {
            type: aws_cdk_lib_1.aws_apigateway.ResponseType.DEFAULT_4XX,
            responseHeaders: corsResponseHeaders,
        });
        promptApi.addGatewayResponse("Default5XX", {
            type: aws_cdk_lib_1.aws_apigateway.ResponseType.DEFAULT_5XX,
            responseHeaders: corsResponseHeaders,
        });
        const promptResource = promptApi.root.addResource("prompt");
        promptResource.addMethod("GET", new aws_cdk_lib_1.aws_apigateway.LambdaIntegration(promptManager));
        promptResource.addMethod("PUT", new aws_cdk_lib_1.aws_apigateway.LambdaIntegration(promptManager));
        new aws_cdk_lib_1.CfnOutput(this, "PromptAPIEndpoint", {
            value: promptApi.url.replace(/\/$/, ''),
            description: "Prompt management API endpoint",
        });
        // Deploy prompt-config.js so the dashboard can find the prompt API
        if (props.demoBucket) {
            new aws_cdk_lib_1.aws_s3_deployment.BucketDeployment(this, "DeployPromptConfig", {
                sources: [aws_cdk_lib_1.aws_s3_deployment.Source.data("prompt-config.js", `window.PROMPT_CONFIG={apiEndpoint:"${promptApi.url.replace(/\/$/, '')}"};`)],
                destinationBucket: props.demoBucket,
                destinationKeyPrefix: "website",
                prune: false,
            });
        }
    }
}
exports.AutoRevocationStack = AutoRevocationStack;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0by1yZXZvY2F0aW9uLXN0YWNrLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiYXV0by1yZXZvY2F0aW9uLXN0YWNrLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQTs7Ozs7Ozs7OztHQVVHOzs7QUFFSCw2Q0FjcUI7QUFXckIsTUFBYSxtQkFBb0IsU0FBUSxtQkFBSztJQUU1QyxZQUFZLEtBQWdCLEVBQUUsRUFBVSxFQUFFLEtBQStCO1FBQ3ZFLEtBQUssQ0FBQyxLQUFLLEVBQUUsRUFBRSxFQUFFLEtBQUssQ0FBQyxDQUFDO1FBRXhCLE1BQU0sTUFBTSxHQUFHLEtBQUssQ0FBQyxNQUFNLENBQUM7UUFDNUIsTUFBTSxhQUFhLEdBQUcsTUFBTSxDQUFDLE9BQU8sRUFBRSxNQUFNLElBQUksSUFBSSxDQUFDLE1BQU0sQ0FBQztRQUM1RCxNQUFNLFlBQVksR0FBRyxNQUFNLENBQUMsT0FBTyxFQUFFLEtBQUssSUFBSSx1QkFBdUIsQ0FBQztRQUV0RSx5RUFBeUU7UUFDekUsTUFBTSxRQUFRLEdBQUcsSUFBSSx3QkFBTSxDQUFDLFFBQVEsQ0FBQyxJQUFJLEVBQUUsaUJBQWlCLEVBQUU7WUFDNUQsT0FBTyxFQUFFLHdCQUFNLENBQUMsT0FBTyxDQUFDLFdBQVc7WUFDbkMsT0FBTyxFQUFFLDBCQUEwQjtZQUNuQyxJQUFJLEVBQUUsd0JBQU0sQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLFFBQVEsQ0FBQztZQUNyQyxPQUFPLEVBQUUsc0JBQVEsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDO1lBQzVCLFVBQVUsRUFBRSxHQUFHO1lBQ2YsV0FBVyxFQUFFO2dCQUNYLE9BQU8sRUFBRSxLQUFLLENBQUMsT0FBTyxDQUFDLGdCQUFnQjtnQkFDdkMsY0FBYyxFQUFFLGFBQWE7Z0JBQzdCLGFBQWEsRUFBRSxZQUFZO2FBQzVCO1NBQ0YsQ0FBQyxDQUFDO1FBRUgsaURBQWlEO1FBQ2pELFFBQVEsQ0FBQyxjQUFjLENBQUMsSUFBSSxzQ0FBWSxDQUFD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Y0FBYyxHQUFHLFNBQVMsQ0FBQyxJQUFJLENBQUMsV0FBVyxDQUFDLFFBQVEsQ0FBQyxDQUFDO1FBQzVELGNBQWMsQ0FBQyxTQUFTLENBQUMsS0FBSyxFQUFFLElBQUksNEJBQVUsQ0FBQyxpQkFBaUIsQ0FBQyxhQUFhLENBQUMsQ0FBQyxDQUFDO1FBQ2pGLGNBQWMsQ0FBQyxTQUFTLENBQUMsS0FBSyxFQUFFLElBQUksNEJBQVUsQ0FBQyxpQkFBaUIsQ0FBQyxhQUFhLENBQUMsQ0FBQyxDQUFDO1FBRWpGLElBQUksdUJBQVMsQ0FBQyxJQUFJLEVBQUUsbUJBQW1CLEVBQUU7WUFDdkMsS0FBSyxFQUFFLFNBQVMsQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLEtBQUssRUFBRSxFQUFFLENBQUM7WUFDdkMsV0FBVyxFQUFFLGdDQUFnQztTQUM5QyxDQUFDLENBQUM7UUFFSCxtRUFBbUU7UUFDbkUsSUFBSSxLQUFLLENBQUMsVUFBVSxFQUFFLENBQUM7WUFDckIsSUFBSSwrQkFBUSxDQUFDLGdCQUFnQixDQUFDLElBQUksRUFBRSxvQkFBb0IsRUFBRTtnQkFDeEQsT0FBTyxFQUFFLENBQUMsK0JBQVEsQ0FBQyxNQUFNLENBQUMsSUFBSSxDQUFDLGtCQUFrQixFQUMvQyxzQ0FBc0MsU0FBUyxDQUFDLEdBQUcsQ0FBQyxPQUFPLENBQUMsS0FBSyxFQUFDLEVBQUUsQ0FBQyxLQUFLLENBQzNFLENBQUM7Z0JBQ0YsaUJBQWlCLEVBQUUsS0FBSyxDQUFDLFVBQVU7Z0JBQ25DLG9CQUFvQixFQUFFLFNBQVM7Z0JBQy9CLEtBQUssRUFBRSxLQUFLO2FBQ2IsQ0FBQyxDQUFDO1FBQ0wsQ0FBQztJQUNILENBQUM7Q0FDRjtBQTdHRCxrREE2R0MiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIENUQSBBdXRvLVJldm9jYXRpb24gU3RhY2sgKG9wdGlvbmFsKVxuICpcbiAqIEFkZHMgQUktcG93ZXJlZCBzZXNzaW9uIGFuYWx5c2lzIHRvIHRoZSByZWFsLXRpbWUgbG9nIHBpcGVsaW5lLlxuICogQ29uc3VtZXMgdGhlIEtpbmVzaXMgc3RyZWFtIGNyZWF0ZWQgYnkgdGhlIG1haW4gc3RhY2ssIGFuYWx5emVzXG4gKiBzZXNzaW9uIHBhdHRlcm5zIHdpdGggQmVkcm9jayBOb3ZhIFBybywgYW5kIHJldm9rZXMgc3VzcGljaW91c1xuICogc2Vzc2lvbnMgaW4gQ2xvdWRGcm9udCBLZXlWYWx1ZVN0b3JlLlxuICpcbiAqIFRoZSBtYWluIHN0YWNrIGhhbmRsZXM6IEtpbmVzaXMgc3RyZWFtLCBSZWFsdGltZUxvZ0NvbmZpZywgZGFzaGJvYXJkLlxuICogVGhpcyBzdGFjayBhZGRzOiBMYW1iZGEgY29uc3VtZXIgKyBCZWRyb2NrIGFuYWx5c2lzLlxuICovXG5cbmltcG9ydCB7XG4gIFN0YWNrLFxuICBTdGFja1Byb3BzLFxuICBEdXJhdGlvbixcbiAgQ2ZuT3V0cHV0LFxuICBhd3Nfa2luZXNpcyBhcyBraW5lc2lzLFxuICBhd3NfbGFtYmRhIGFzIGxhbWJkYSxcbiAgYXdzX2xhbWJkYV9ldmVudF9zb3VyY2VzIGFzIGV2ZW50c291cmNlcyxcbiAgYXdzX2Nsb3VkZnJvbnQgYXMgY2xvdWRmcm9udCxcbiAgYXdzX2lhbSBhcyBpYW0sXG4gIGF3c19zc20gYXMgc3NtLFxuICBhd3NfczMgYXMgczMsXG4gIGF3c19zM19kZXBsb3ltZW50IGFzIHMzZGVwbG95LFxuICBhd3NfYXBpZ2F0ZXdheSBhcyBhcGlnYXRld2F5LFxufSBmcm9tIFwiYXdzLWNkay1saWJcIjtcblxuaW1wb3J0IHsgQ29uc3RydWN0IH0gZnJvbSBcImNvbnN0cnVjdHNcIjtcblxuZXhwb3J0IGludGVyZmFjZSBBdXRvUmV2b2NhdGlvblN0YWNrUHJvcHMgZXh0ZW5kcyBTdGFja1Byb3BzIHtcbiAgcmVhZG9ubHkga3ZTdG9yZTogY2xvdWRmcm9udC5LZXlWYWx1ZVN0b3JlO1xuICByZWFkb25seSBsb2dTdHJlYW06IGtpbmVzaXMuU3RyZWFtO1xuICByZWFkb25seSBkZW1vQnVja2V0PzogczMuSUJ1Y2tldDtcbiAgcmVhZG9ubHkgY29uZmlnOiBhbnk7XG59XG5cbmV4cG9ydCBjbGFzcyBBdXRvUmV2b2NhdGlvblN0YWNrIGV4dGVuZHMgU3RhY2sge1xuXG4gIGNvbnN0cnVjdG9yKHNjb3BlOiBDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIHByb3BzOiBBdXRvUmV2b2NhdGlvblN0YWNrUHJvcHMpIHtcbiAgICBzdXBlcihzY29wZSwgaWQsIHByb3BzKTtcblxuICAgIGNvbnN0IGNvbmZpZyA9IHByb3BzLmNvbmZpZztcbiAgICBjb25zdCBiZWRyb2NrUmVnaW9uID0gY29uZmlnLmJlZHJvY2s/LnJlZ2lvbiB8fCB0aGlzLnJlZ2lvbjtcbiAgICBjb25zdCBiZWRyb2NrTW9kZWwgPSBjb25maWcuYmVkcm9jaz8ubW9kZWwgfHwgXCJhbWF6b24ubm92YS1saXRlLXYxOjBcIjtcblxuICAgIC8vIEtpbmVzaXMgc3RyZWFtIHByb2Nlc3NvciDigJQgYWdncmVnYXRlcyBzZXNzaW9ucywgY2FsbHMgQmVkcm9jaywgcmV2b2tlc1xuICAgIGNvbnN0IGFuYWx5emVyID0gbmV3IGxhbWJkYS5GdW5jdGlvbih0aGlzLCBcIktpbmVzaXNBbmFseXplclwiLCB7XG4gICAgICBydW50aW1lOiBsYW1iZGEuUnVudGltZS5OT0RFSlNfMjJfWCxcbiAgICAgIGhhbmRsZXI6IFwia2luZXNpc19hbmFseXplci5oYW5kbGVyXCIsXG4gICAgICBjb2RlOiBsYW1iZGEuQ29kZS5mcm9tQXNzZXQoXCJsYW1iZGFcIiksXG4gICAgICB0aW1lb3V0OiBEdXJhdGlvbi5taW51dGVzKDUpLFxuICAgICAgbWVtb3J5U2l6ZTogNTEyLFxuICAgICAgZW52aXJvbm1lbnQ6IHtcbiAgICAgICAgS1ZTX0FSTjogcHJvcHMua3ZTdG9yZS5rZXlWYWx1ZVN0b3JlQXJuLFxuICAgICAgICBCRURST0NLX1JFR0lPTjogYmVkcm9ja1JlZ2lvbixcbiAgICAgICAgQkVEUk9DS19NT0RFTDogYmVkcm9ja01vZGVsLFxuICAgICAgfSxcbiAgICB9KTtcblxuICAgIC8vIENvbnN1bWUgdGhlIEtpbmVzaXMgc3RyZWFtIGZyb20gdGhlIG1haW4gc3RhY2tcbiAgICBhbmFseXplci5hZGRFdmVudFNvdXJjZShuZXcgZXZlbnRzb3VyY2VzLktpbmVzaXNFdmVudFNvdXJjZShwcm9wcy5sb2dTdHJlYW0sIHtcbiAgICAgIHN0YXJ0aW5nUG9zaXRpb246IGxhbWJkYS5TdGFydGluZ1Bvc2l0aW9uLkxBVEVTVCxcbiAgICAgIGJhdGNoU2l6ZTogNTAwLFxuICAgICAgbWF4QmF0Y2hpbmdXaW5kb3c6IER1cmF0aW9uLnNlY29uZHMoNjApLFxuICAgICAgcmV0cnlBdHRlbXB0czogMixcbiAgICB9KSk7XG5cbiAgICAvLyBCZWRyb2NrIHBlcm1pc3Npb25zXG4gICAgYW5hbHl6ZXIuYWRkVG9Sb2xlUG9saWN5KG5ldyBpYW0uUG9saWN5U3RhdGVtZW50KHtcbiAgICAgIGFjdGlvbnM6IFtcImJlZHJvY2s6SW52b2tlTW9kZWxcIl0sXG4gICAgICByZXNvdXJjZXM6IFtgYXJuOmF3czpiZWRyb2NrOiR7YmVkcm9ja1JlZ2lvbn06OmZvdW5kYXRpb24tbW9kZWwvJHtiZWRyb2NrTW9kZWx9YF0sXG4gICAgfSkpO1xuXG4gICAgLy8gS1ZTIHBlcm1pc3Npb25zIGZvciB3cml0aW5nIHJldm9jYXRpb25zXG4gICAgYW5hbHl6ZXIuYWRkVG9Sb2xlUG9saWN5KG5ldyBpYW0uUG9saWN5U3RhdGVtZW50KHtcbiAgICAgIGFjdGlvbnM6IFtcImNsb3VkZnJvbnQta2V5dmFsdWVzdG9yZTpQdXRLZXlcIiwgXCJjbG91ZGZyb250LWtleXZhbHVlc3RvcmU6RGVzY3JpYmVLZXlWYWx1ZVN0b3JlXCJdLFxuICAgICAgcmVzb3VyY2VzOiBbcHJvcHMua3ZTdG9yZS5rZXlWYWx1ZVN0b3JlQXJuXSxcbiAgICB9KSk7XG5cbiAgICAvLyAtLS0gRWRpdGFibGUgQmVkcm9jayBQcm9tcHQgdmlhIFNTTSBQYXJhbWV0ZXIgU3RvcmUgLS0tXG4gICAgY29uc3QgcHJvbXB0UGFyYW0gPSBuZXcgc3NtLlN0cmluZ1BhcmFtZXRlcih0aGlzLCBcIkJlZHJvY2tQcm9tcHRcIiwge1xuICAgICAgcGFyYW1ldGVyTmFtZTogYC8ke3RoaXMuc3RhY2tOYW1lfS9iZWRyb2NrLXByb21wdGAsXG4gICAgICBzdHJpbmdWYWx1ZTogXCJZb3UgYXJlIGEgdmlkZW8gc3RyZWFtaW5nIHNlY3VyaXR5IGFuYWx5c3QuIEFuYWx5emUgdGhlc2UgQ1RBLTUwMDctQiB0b2tlbiBzZXNzaW9uIG1ldHJpY3MgZnJvbSBDbG91ZEZyb250IHJlYWwtdGltZSBsb2dzIGFuZCBpZGVudGlmeSBzZXNzaW9ucyB0aGF0IHNob3VsZCBiZSByZXZva2VkIGR1ZSB0byB1bmF1dGhvcml6ZWQgc2hhcmluZyBvciBhYnVzZS5cXG5cXG5FYWNoIHNlc3Npb24gcmVwcmVzZW50cyBhIHVuaXF1ZSBDVEEgdG9rZW4gYmVpbmcgdXNlZCB0byBhY2Nlc3MgcHJvdGVjdGVkIHZpZGVvIGNvbnRlbnQgdGhyb3VnaCBDbG91ZEZyb250LlxcblxcbiMjIEluZGljYXRvcnMgb2YgVG9rZW4gU2hhcmluZyAvIEFidXNlXFxuLSBNdWx0aXBsZSBkaXN0aW5jdCBJUCBhZGRyZXNzZXMgdXNpbmcgdGhlIHNhbWUgdG9rZW4gKHN0cm9uZ2VzdCBzaWduYWwpXFxuLSBSZXF1ZXN0cyBmcm9tIG11bHRpcGxlIGNvdW50cmllcyB3aXRoIHRoZSBzYW1lIHRva2VuXFxuLSBNdWx0aXBsZSBkaWZmZXJlbnQgVXNlci1BZ2VudCBzdHJpbmdzIChkaWZmZXJlbnQgZGV2aWNlcy9icm93c2VycylcXG4tIEFibm9ybWFsbHkgaGlnaCByZXF1ZXN0IHJhdGVzIChhdXRvbWF0ZWQgc2NyYXBpbmcpXFxuLSBIaWdoIGVycm9yIHJhdGVzIGNvbWJpbmVkIHdpdGggaGlnaCByZXF1ZXN0IHZvbHVtZSAoYnJ1dGUgZm9yY2UpXFxuXFxuIyMgSW5kaWNhdG9ycyBvZiBMZWdpdGltYXRlIFVzZVxcbi0gU2luZ2xlIElQLCBzaW5nbGUgY291bnRyeSwgc2luZ2xlIFVzZXItQWdlbnQgPSBub3JtYWwgdmlld2VyXFxuLSBNb2RlcmF0ZSByZXF1ZXN0IHJhdGVzICgxLTUgcmVxdWVzdHMvc2VjIGlzIG5vcm1hbCBmb3IgYWRhcHRpdmUgc3RyZWFtaW5nKVxcbi0gSVAgY2hhbmdlcyB3aXRoaW4gdGhlIHNhbWUgY291bnRyeSBjb3VsZCBiZSBtb2JpbGUgbmV0d29yayBoYW5kb2ZmIChsZXNzIHN1c3BpY2lvdXMpXFxuXFxuIyMgSW5zdHJ1Y3Rpb25zXFxuUmVzcG9uZCB3aXRoIE9OTFkgYSBKU09OIGFycmF5IG9mIHNlc3Npb24ga2V5cyB0aGF0IHNob3VsZCBiZSByZXZva2VkLiBJZiBubyBzZXNzaW9ucyBzaG91bGQgYmUgcmV2b2tlZCwgcmVzcG9uZCB3aXRoIGFuIGVtcHR5IGFycmF5IFtdLlxcbkJlIGNvbnNlcnZhdGl2ZSDigJQgb25seSByZXZva2Ugc2Vzc2lvbnMgd2l0aCBzdHJvbmcgZXZpZGVuY2Ugb2Ygc2hhcmluZyBvciBhYnVzZS5cIixcbiAgICB9KTtcblxuICAgIC8vIFBhc3MgU1NNIHBhcmFtIG5hbWUgdG8gdGhlIGFuYWx5emVyIExhbWJkYVxuICAgIGFuYWx5emVyLmFkZEVudmlyb25tZW50KFwiUFJPTVBUX1BBUkFNXCIsIHByb21wdFBhcmFtLnBhcmFtZXRlck5hbWUpO1xuICAgIHByb21wdFBhcmFtLmdyYW50UmVhZChhbmFseXplcik7XG5cbiAgICAvLyBQcm9tcHQgbWFuYWdlbWVudCBBUElcbiAgICBjb25zdCBwcm9tcHRNYW5hZ2VyID0gbmV3IGxhbWJkYS5GdW5jdGlvbih0aGlzLCBcIlByb21wdE1hbmFnZXJcIiwge1xuICAgICAgcnVudGltZTogbGFtYmRhLlJ1bnRpbWUuTk9ERUpTXzIyX1gsXG4gICAgICBoYW5kbGVyOiBcInByb21wdF9tYW5hZ2VyLmhhbmRsZXJcIixcbiAgICAgIGNvZGU6IGxhbWJkYS5Db2RlLmZyb21Bc3NldChcImxhbWJkYVwiKSxcbiAgICAgIHRpbWVvdXQ6IER1cmF0aW9uLnNlY29uZHMoMTApLFxuICAgICAgZW52aXJvbm1lbnQ6IHsgUFJPTVBUX1BBUkFNOiBwcm9tcHRQYXJhbS5wYXJhbWV0ZXJOYW1lIH0sXG4gICAgfSk7XG4gICAgcHJvbXB0UGFyYW0uZ3JhbnRSZWFkKHByb21wdE1hbmFnZXIpO1xuICAgIHByb21wdFBhcmFtLmdyYW50V3JpdGUocHJvbXB0TWFuYWdlcik7XG5cbiAgICBjb25zdCBwcm9tcHRBcGkgPSBuZXcgYXBpZ2F0ZXdheS5SZXN0QXBpKHRoaXMsIFwiUHJvbXB0QVBJXCIsIHtcbiAgICAgIHJlc3RBcGlOYW1lOiBcIkNUQSBQcm9tcHQgQVBJXCIsXG4gICAgICBkZWZhdWx0Q29yc1ByZWZsaWdodE9wdGlvbnM6IHtcbiAgICAgICAgYWxsb3dPcmlnaW5zOiBhcGlnYXRld2F5LkNvcnMuQUxMX09SSUdJTlMsXG4gICAgICAgIGFsbG93TWV0aG9kczogYXBpZ2F0ZXdheS5Db3JzLkFMTF9NRVRIT0RTLFxuICAgICAgfSxcbiAgICB9KTtcblxuICAgIC8vIEF0dGFjaCBDT1JTIGhlYWRlcnMgdG8gZGVmYXVsdCBnYXRld2F5IHJlc3BvbnNlcyBzbyBpbnRlZ3JhdGlvbiBlcnJvcnNcbiAgICAvLyAoTGFtYmRhIDV4eC90aW1lb3V0LCBvciBhIDR4eCkgc3RpbGwgY2FycnkgQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luXG4gICAgLy8gaW5zdGVhZCBvZiBzdXJmYWNpbmcgaW4gdGhlIGJyb3dzZXIgYXMgYSBtaXNsZWFkaW5nIENPUlMgZXJyb3IuXG4gICAgY29uc3QgY29yc1Jlc3BvbnNlSGVhZGVycyA9IHtcbiAgICAgIFwiQWNjZXNzLUNvbnRyb2wtQWxsb3ctT3JpZ2luXCI6IFwiJyonXCIsXG4gICAgICBcIkFjY2Vzcy1Db250cm9sLUFsbG93LUhlYWRlcnNcIjogXCInKidcIixcbiAgICB9O1xuICAgIHByb21wdEFwaS5hZGRHYXRld2F5UmVzcG9uc2UoXCJEZWZhdWx0NFhYXCIsIHtcbiAgICAgIHR5cGU6IGFwaWdhdGV3YXkuUmVzcG9uc2VUeXBlLkRFRkFVTFRfNFhYLFxuICAgICAgcmVzcG9uc2VIZWFkZXJzOiBjb3JzUmVzcG9uc2VIZWFkZXJzLFxuICAgIH0pO1xuICAgIHByb21wdEFwaS5hZGRHYXRld2F5UmVzcG9uc2UoXCJEZWZhdWx0NVhYXCIsIHtcbiAgICAgIHR5cGU6IGFwaWdhdGV3YXkuUmVzcG9uc2VUeXBlLkRFRkFVTFRfNVhYLFxuICAgICAgcmVzcG9uc2VIZWFkZXJzOiBjb3JzUmVzcG9uc2VIZWFkZXJzLFxuICAgIH0pO1xuXG4gICAgY29uc3QgcHJvbXB0UmVzb3VyY2UgPSBwcm9tcHRBcGkucm9vdC5hZGRSZXNvdXJjZShcInByb21wdFwiKTtcbiAgICBwcm9tcHRSZXNvdXJjZS5hZGRNZXRob2QoXCJHRVRcIiwgbmV3IGFwaWdhdGV3YXkuTGFtYmRhSW50ZWdyYXRpb24ocHJvbXB0TWFuYWdlcikpO1xuICAgIHByb21wdFJlc291cmNlLmFkZE1ldGhvZChcIlBVVFwiLCBuZXcgYXBpZ2F0ZXdheS5MYW1iZGFJbnRlZ3JhdGlvbihwcm9tcHRNYW5hZ2VyKSk7XG5cbiAgICBuZXcgQ2ZuT3V0cHV0KHRoaXMsIFwiUHJvbXB0QVBJRW5kcG9pbnRcIiwge1xuICAgICAgdmFsdWU6IHByb21wdEFwaS51cmwucmVwbGFjZSgvXFwvJC8sICcnKSxcbiAgICAgIGRlc2NyaXB0aW9uOiBcIlByb21wdCBtYW5hZ2VtZW50IEFQSSBlbmRwb2ludFwiLFxuICAgIH0pO1xuXG4gICAgLy8gRGVwbG95IHByb21wdC1jb25maWcuanMgc28gdGhlIGRhc2hib2FyZCBjYW4gZmluZCB0aGUgcHJvbXB0IEFQSVxuICAgIGlmIChwcm9wcy5kZW1vQnVja2V0KSB7XG4gICAgICBuZXcgczNkZXBsb3kuQnVja2V0RGVwbG95bWVudCh0aGlzLCBcIkRlcGxveVByb21wdENvbmZpZ1wiLCB7XG4gICAgICAgIHNvdXJjZXM6IFtzM2RlcGxveS5Tb3VyY2UuZGF0YShcInByb21wdC1jb25maWcuanNcIixcbiAgICAgICAgICBgd2luZG93LlBST01QVF9DT05GSUc9e2FwaUVuZHBvaW50OlwiJHtwcm9tcHRBcGkudXJsLnJlcGxhY2UoL1xcLyQvLCcnKX1cIn07YFxuICAgICAgICApXSxcbiAgICAgICAgZGVzdGluYXRpb25CdWNrZXQ6IHByb3BzLmRlbW9CdWNrZXQsXG4gICAgICAgIGRlc3RpbmF0aW9uS2V5UHJlZml4OiBcIndlYnNpdGVcIixcbiAgICAgICAgcHJ1bmU6IGZhbHNlLFxuICAgICAgfSk7XG4gICAgfVxuICB9XG59XG4iXX0=