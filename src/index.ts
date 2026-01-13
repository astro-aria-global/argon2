import { Hono } from "hono";
import { handle } from "hono/vercel";
import * as argon2 from "argon2";
import * as crypto from "crypto";

// This is a helper script to run resource-intensive argon2.verify() on vercel.

type Variables = {
  requestBody: {
    inputPassword?: string;
    hashedValue?: string;
  };
};
type RequestBody = Variables["requestBody"];

const app = new Hono<{ Variables: Variables }>();

// Step 1: Import environment variables
const rawHmacCfToVercel = process.env.HMAC_CF_TO_VERCEL;
const rawHmacVercelToCf = process.env.HMAC_VERCEL_TO_CF;

if (!rawHmacCfToVercel || !rawHmacVercelToCf) {
  throw new Error("Missing environment variables");
}

// Helper function for HMAC calculation
const hmacCalc = (content: string, key: string): string => {
  return crypto.createHmac("sha256", key).update(content).digest("hex");
};

// Helper function to sleep for given time
const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

// Middleware for request validation
app.use("/", async (c, next) => {
  // 1. Check signature header
  const requestSignature = c.req.header("X-Aria-Request-Sig");
  if (!requestSignature) {
    return c.json({ success: false, errcode: "MISSING_SIGNATURE" }, 401);
  }

  // 2. Fetch raw body
  const rawBody = await c.req.text();

  // 3. Verify signature status
  const expectedSignature = hmacCalc(rawBody, rawHmacCfToVercel);
  const source = Buffer.from(requestSignature);
  const target = Buffer.from(expectedSignature);
  if (
    source.length !== target.length ||
    !crypto.timingSafeEqual(source, target)
  ) {
    return c.json({ success: false, errcode: "INVALID_SIGNATURE" }, 401);
  }

  // 4. Parse body into json
  try {
    const parsedBody = JSON.parse(rawBody);
    c.set("requestBody", parsedBody);
  } catch (error) {
    console.error(
      "Parsing request body failed:",
      error instanceof Error ? error.name : "UnknownError",
    );
    return c.json({ success: false, errcode: "INVALID_BODY" }, 400);
  }

  await next();
});

// Middleware for response signing
app.use("/", async (c, next) => {
  await next();

  // 1. Fetch response body
  const responseClone = c.res.clone();
  const responseBody = await responseClone.text();

  // 2. Sign the response body
  const responseSignature = hmacCalc(responseBody, rawHmacVercelToCf);

  // 3. Set response header
  c.res.headers.set("X-Aria-Response-Sig", responseSignature);
});

app.post("/", async (c) => {
  // Step 2: Mark start time for time padding
  const startTime = Date.now();

  // Step 3: Fetch parsed request body
  const body = c.get("requestBody") as RequestBody | undefined;

  // Step 4: Verify params existence
  if (
    !body ||
    typeof body !== "object" ||
    !("inputPassword" in body) ||
    !("hashedValue" in body) ||
    typeof body.inputPassword !== "string" ||
    typeof body.hashedValue !== "string"
  ) {
    return c.json({ success: false, errcode: "MISSING_PARAMS" }, 400);
  }

  const { inputPassword, hashedValue } = body;

  // Step 5: Run argon2.verify()
  try {
    const isVerified = await argon2.verify(hashedValue, inputPassword);

    // Make sure function runs more than limit
    const minExecutionTime = 250;
    const elapsedTime = Date.now() - startTime;
    if (elapsedTime < minExecutionTime) {
      await sleep(minExecutionTime - elapsedTime);
    }

    if (isVerified) {
      return c.json({ success: true });
    } else {
      return c.json({ success: false, errcode: "PASSWORD_MISMATCH" });
    }
  } catch (error) {
    console.error(
      "Argon2 process failed:",
      error instanceof Error ? error.name : "UnknownError",
    );
    return c.json({ success: false, errcode: "VERIFICATION_ERROR" }, 500);
  }
});

export const POST = handle(app);
export default app;
