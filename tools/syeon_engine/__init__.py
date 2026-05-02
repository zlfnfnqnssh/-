"""서연(syeon) Linux 점검·판정 엔진 (자기 코드 그대로 보존).

이 패키지는 서연 origin/syeon 브랜치의 core/ + main.py 를 통째로 가져온 것이다.
서연이 향후 자기 브랜치를 push 하면 다음 명령으로 갱신 가능:

    git checkout origin/syeon -- core/
    mv core/*.py tools/syeon_engine/
    rmdir core/
    git show origin/syeon:main.py > tools/syeon_engine/main.py

본인(riri) 시스템에서 호출 흐름:
    from tools.syeon_engine.main import run_pipeline   ← 본인 web/routes/scan.py 가 호출

DB 저장은 서연 db_writer.py 가 아니라 integration/syeon_db_adapter.py 가 담당
(SQLite → PostgreSQL vs_* 테이블로 변환).
"""

import sys
from pathlib import Path

# 서연 main.py 가 'from runner import ScriptRunner' 같은 절대 import 사용
# tools/syeon_engine/ 자체를 sys.path 에 추가해야 동작
_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))
