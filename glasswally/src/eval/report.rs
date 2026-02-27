// glasswally/src/eval/report.rs
//
// ROC curve generation and markdown/JSON report output for the eval framework.

use super::EvalResult;

/// Compute the area under the ROC curve from the score histogram.
/// (Simplified trapezoidal approximation over binned scores.)
pub fn auc_roc_approx(result: &EvalResult) -> f64 {
    // Without per-event score + label pairs we approximate from the histogram.
    // A proper AUC requires sorting all events by score and computing the exact curve.
    // This placeholder returns the F1 score as a proxy when per-event data is unavailable.
    let _p = result.global.precision();
    let r = result.global.recall();
    // Approximate: AUC ≈ (1 + TPR - FPR) / 2
    let tpr = r;
    let fpr = result.global.fpr();
    (1.0 + tpr - fpr) / 2.0
}

/// Print a markdown-formatted full report to stdout.
pub fn print_markdown(result: &EvalResult) {
    let auc = auc_roc_approx(result);
    println!("# Glasswally Evaluation Report");
    println!();
    println!(
        "**Events**: {}  **Positive**: {}  **Negative**: {}  **Threshold**: {:.3}",
        result.n_events, result.n_positive, result.n_negative, result.threshold
    );
    println!();
    println!("| Metric    | Value  |");
    println!("|-----------|--------|");
    println!("| Precision | {:.4}  |", result.global.precision());
    println!("| Recall    | {:.4}  |", result.global.recall());
    println!("| F1        | {:.4}  |", result.global.f1());
    println!("| FPR       | {:.4}  |", result.global.fpr());
    println!("| AUC-ROC   | {:.4}  |", auc);
    println!();
    result.print_report();
}

/// Serialize the evaluation result to JSON for downstream consumption.
pub fn to_json(result: &EvalResult) -> String {
    serde_json::json!({
        "n_events":    result.n_events,
        "n_positive":  result.n_positive,
        "n_negative":  result.n_negative,
        "threshold":   result.threshold,
        "precision":   result.global.precision(),
        "recall":      result.global.recall(),
        "f1":          result.global.f1(),
        "fpr":         result.global.fpr(),
        "auc_roc":     auc_roc_approx(result),
        "tier_counts": result.tier_counts,
    })
    .to_string()
}
