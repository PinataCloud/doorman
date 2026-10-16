/**
 * Where the Doorman fine-tuned injection model (`doorman-1`) is downloaded
 * from — the ONE value to change when a new revision is published.
 *
 * A pinned-revision Hugging Face URL, ending in a slash, the same form as the
 * stock model's (lib/model-assets.ts PROMPT_GUARD_2_22M):
 *
 *   https://huggingface.co/<org>/<repo>/resolve/<commit>/
 *
 * Here: PinataCloud/Llama-Doorman-22M at commit 4a43fec6. Pin a COMMIT, never
 * `main`: every file is still verified against the size and sha256 pins in
 * lib/model-assets.ts (PROMPT_GUARD_2_22M_DOORMAN_1), so a moved branch or a
 * re-uploaded file is refused, never run.
 *
 * DOORMAN_INJECTION_CLASSIFIER_SOURCE, when set, always wins. Empty would
 * mean "not published": the app then runs the stock Prompt Guard 2 model in
 * its place, as it also does whenever this URL cannot be fetched.
 */
export const DOORMAN_MODEL_BASE_URL = "https://huggingface.co/PinataCloud/Llama-Doorman-22M/resolve/4a43fec65a670e48835d8e8c85c705b4b0d1c907/";
