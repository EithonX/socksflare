export const REQUEST_BODY_LIMIT_ERROR = 'Request body exceeded maxUploadBytes';
export const RESPONSE_BODY_LIMIT_ERROR = 'Response body exceeded maxResponseBytes';

export function normalizeOptionalByteLimit(value, optionName) {
    if (value == null) return null;
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new Error(`socksflare: ${optionName} must be a finite safe integer >= 0`);
    }
    return value;
}

export function isByteLimitExceededError(err) {
    return !!(err && (
        err.message === REQUEST_BODY_LIMIT_ERROR ||
        err.message === RESPONSE_BODY_LIMIT_ERROR
    ));
}
