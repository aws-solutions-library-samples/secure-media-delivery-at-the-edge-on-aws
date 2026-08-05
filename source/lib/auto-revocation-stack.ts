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

import {
  Stack,
  StackProps,
  Duration,
  CfnOutput,
  aws_kinesis as kinesis,
  aws_lambda as lambda,
  aws_lambda_event_sources as eventsources,
  aws_cloudfront as cloudfront,
  aws_iam as iam,
  aws_ssm as ssm,
  aws_s3 as s3,
  aws_s3_deployment as s3deploy,
  aws_apigateway as apigateway,
} from "aws-cdk-lib";

import { Construct } from "constructs";

export interface AutoRevocationStackProps extends StackProps {
  readonly kvStore: cloudfront.KeyValueStore;
  readonly logStream: kinesis.Stream;
  readonly demoBucket?: s3.IBucket;
  readonly config: any;
}

export class AutoRevocationStack extends Stack {

  constructor(scope: Construct, id: string, props: AutoRevocationStackProps) {
    super(scope, id, props);

    const config = props.config;
    const bedrockRegion = config.bedrock?.region || this.region;
    const bedrockModel = config.bedrock?.model || "amazon.nova-lite-v1:0";

    // Kinesis stream processor — aggregates sessions, calls Bedrock, revokes
    const analyzer = new lambda.Function(this, "KinesisAnalyzer", {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: "kinesis_analyzer.handler",
      code: lambda.Code.fromAsset("lambda"),
      timeout: Duration.minutes(5),
      memorySize: 512,
      environment: {
        KVS_ARN: props.kvStore.keyValueStoreArn,
        BEDROCK_REGION: bedrockRegion,
        BEDROCK_MODEL: bedrockModel,
      },
    });

    // Consume the Kinesis stream from the main stack
    analyzer.addEventSource(new eventsources.KinesisEventSource(props.logStream, {
      startingPosition: lambda.StartingPosition.LATEST,
      batchSize: 500,
      maxBatchingWindow: Duration.seconds(60),
      retryAttempts: 2,
    }));

    // Bedrock permissions
    analyzer.addToRolePolicy(new iam.PolicyStatement({
      actions: ["bedrock:InvokeModel"],
      resources: [`arn:aws:bedrock:${bedrockRegion}::foundation-model/${bedrockModel}`],
    }));

    // KVS permissions for writing revocations
    analyzer.addToRolePolicy(new iam.PolicyStatement({
      actions: ["cloudfront-keyvaluestore:PutKey", "cloudfront-keyvaluestore:DescribeKeyValueStore"],
      resources: [props.kvStore.keyValueStoreArn],
    }));

    // --- Editable Bedrock Prompt via SSM Parameter Store ---
    const promptParam = new ssm.StringParameter(this, "BedrockPrompt", {
      parameterName: `/${this.stackName}/bedrock-prompt`,
      stringValue: "You are a video streaming security analyst. Analyze these CTA-5007-B token session metrics from CloudFront real-time logs and identify sessions that should be revoked due to unauthorized sharing or abuse.\n\nEach session represents a unique CTA token being used to access protected video content through CloudFront.\n\n## Indicators of Token Sharing / Abuse\n- Multiple distinct IP addresses using the same token (strongest signal)\n- Requests from multiple countries with the same token\n- Multiple different User-Agent strings (different devices/browsers)\n- Abnormally high request rates (automated scraping)\n- High error rates combined with high request volume (brute force)\n\n## Indicators of Legitimate Use\n- Single IP, single country, single User-Agent = normal viewer\n- Moderate request rates (1-5 requests/sec is normal for adaptive streaming)\n- IP changes within the same country could be mobile network handoff (less suspicious)\n\n## Instructions\nRespond with ONLY a JSON array of session keys that should be revoked. If no sessions should be revoked, respond with an empty array [].\nBe conservative — only revoke sessions with strong evidence of sharing or abuse.",
    });

    // Pass SSM param name to the analyzer Lambda
    analyzer.addEnvironment("PROMPT_PARAM", promptParam.parameterName);
    promptParam.grantRead(analyzer);

    // Prompt management API
    const promptManager = new lambda.Function(this, "PromptManager", {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: "prompt_manager.handler",
      code: lambda.Code.fromAsset("lambda"),
      timeout: Duration.seconds(10),
      environment: { PROMPT_PARAM: promptParam.parameterName },
    });
    promptParam.grantRead(promptManager);
    promptParam.grantWrite(promptManager);

    const promptApi = new apigateway.RestApi(this, "PromptAPI", {
      restApiName: "CTA Prompt API",
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
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
      type: apigateway.ResponseType.DEFAULT_4XX,
      responseHeaders: corsResponseHeaders,
    });
    promptApi.addGatewayResponse("Default5XX", {
      type: apigateway.ResponseType.DEFAULT_5XX,
      responseHeaders: corsResponseHeaders,
    });

    const promptResource = promptApi.root.addResource("prompt");
    promptResource.addMethod("GET", new apigateway.LambdaIntegration(promptManager));
    promptResource.addMethod("PUT", new apigateway.LambdaIntegration(promptManager));

    new CfnOutput(this, "PromptAPIEndpoint", {
      value: promptApi.url.replace(/\/$/, ''),
      description: "Prompt management API endpoint",
    });

    // Deploy prompt-config.js so the dashboard can find the prompt API
    if (props.demoBucket) {
      new s3deploy.BucketDeployment(this, "DeployPromptConfig", {
        sources: [s3deploy.Source.data("prompt-config.js",
          `window.PROMPT_CONFIG={apiEndpoint:"${promptApi.url.replace(/\/$/,'')}"};`
        )],
        destinationBucket: props.demoBucket,
        destinationKeyPrefix: "website",
        prune: false,
      });
    }
  }
}
