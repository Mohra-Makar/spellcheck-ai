"""Compare the original detector (v0) with the new one on dataset.csv.

Usage: python evaluate.py [--split dev|holdout|all] [--verbose]
"""
import argparse
import csv
import json
from collections import defaultdict

import detector
import old_detector


def predict_old(text):
    return old_detector.analyze_prompt_security(text)[0]


def predict_new(text):
    return detector.analyze(text).blocked


def metrics(rows, predict):
    tp = fp = tn = fn = 0
    misses, false_pos = [], []
    by_tech = defaultdict(lambda: [0, 0])  # technique -> [caught, total] for attacks
    for r in rows:
        pred = predict(r["text"])
        label = int(r["label"])
        if label and pred: tp += 1
        elif label and not pred: fn += 1; misses.append(r)
        elif not label and pred: fp += 1; false_pos.append(r)
        else: tn += 1
        if label:
            by_tech[r["technique"]][1] += 1
            by_tech[r["technique"]][0] += int(pred)
    attacks, benign = tp + fn, tn + fp
    return {
        "attacks": attacks, "benign": benign, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "detection_rate": round(tp / attacks, 3) if attacks else None,
        "false_positive_rate": round(fp / benign, 3) if benign else None,
        "precision": round(tp / (tp + fp), 3) if (tp + fp) else None,
        "by_technique": {k: f"{v[0]}/{v[1]}" for k, v in sorted(by_tech.items())},
        "missed": [m["text"][:90] for m in misses],
        "false_positives": [m["text"][:90] for m in false_pos],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="all", choices=["dev", "holdout", "all"])
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    with open("dataset.csv", encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if args.split in ("all", r["split"])]

    results = {"split": args.split, "n": len(rows),
               "v0_substring": metrics(rows, predict_old), "v1_engine": metrics(rows, predict_new)}
    for name in ("v0_substring", "v1_engine"):
        m = results[name]
        print(f"\n== {name} ({args.split}, n={len(rows)}) ==")
        print(f"detection rate {m['detection_rate']}  ({m['tp']}/{m['attacks']})   "
              f"false positives {m['fp']}/{m['benign']} ({m['false_positive_rate']})   precision {m['precision']}")
        print("by technique:", m["by_technique"])
        if args.verbose:
            for t in m["missed"]: print("  MISSED:", t)
            for t in m["false_positives"]: print("  FALSE POSITIVE:", t)
    with open(f"results_{args.split}.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
