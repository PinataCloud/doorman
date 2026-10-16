/**
 * Where the Doorman fine-tuned injection model (`doorman-1`) is downloaded
 * from — the ONE value to change when it is published.
 *
 * Set it to a pinned-revision Hugging Face URL, ending in a slash, the same
 * form as the stock model's (lib/model-assets.ts PROMPT_GUARD_2_22M):
 *
 *   https://huggingface.co/<org>/<repo>/resolve/<commit>/
 *
 * Pin a COMMIT, never `main`: every file is still verified against the size
 * and sha256 pins in lib/model-assets.ts (PROMPT_GUARD_2_22M_DOORMAN_1), so
 * publishing means changing this line only — the pins stay as they are.
 *
 * Empty = not published yet. Until it is set (or an operator names a source
 * with DOORMAN_INJECTION_CLASSIFIER_SOURCE, which always wins), the app keeps
 * running the stock Prompt Guard 2 model in its place.
 */
export const DOORMAN_MODEL_BASE_URL = "";
