import { SignJWT, jwtVerify } from "jose";

const ALG = "HS256";
const CHALLENGE_TTL_SEC = 5 * 60;

function getMasterKey(): Uint8Array {
  const secret = process.env.CHALLENGE_VERIFY_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("CHALLENGE_VERIFY_SECRET must be set (min 32 chars)");
  }
  return new TextEncoder().encode(secret);
}

export async function signChallengeToken(challengeId: string): Promise<string> {
  const key = getMasterKey();
  const token = await new SignJWT({ challengeId })
    .setProtectedHeader({ alg: ALG })
    .setIssuedAt()
    .setExpirationTime(`${CHALLENGE_TTL_SEC}s`)
    .sign(key);
  return token;
}

export async function verifyChallengeToken(
  token: string
): Promise<{ challengeId: string }> {
  const key = getMasterKey();
  const { payload } = await jwtVerify(token, key, {
    algorithms: [ALG],
    maxTokenAge: CHALLENGE_TTL_SEC,
  });
  const challengeId = payload.challengeId;
  if (typeof challengeId !== "string" || !challengeId) {
    throw new Error("Invalid challenge token: missing challengeId");
  }
  return { challengeId };
}
