#!/bin/bash
# 下载三套公开代码可读性标注数据集（Buse & Weimer / Dorn / Scalabrino），
# 来源：https://dibt.unimol.it/report/readability/ （Scalabrino 组的 replication 页面）
set -euo pipefail
WORK="$(cd "$(dirname "$0")" && pwd)/.work"
mkdir -p "$WORK/datasets"
cd "$WORK/datasets"
for f in Dataset.zip DatasetBW.zip DatasetDorn.zip; do
  [ -f "$f" ] || curl -sL --max-time 120 -O "https://dibt.unimol.it/report/readability/files/$f"
  unzip -qo "$f"
done
echo "datasets ready at $WORK/datasets"
