-- PENTRON database schema
-- Auto-applied by the MariaDB container on first start
-- (mounted into /docker-entrypoint-initdb.d/)

CREATE TABLE IF NOT EXISTS history (
  sl_no     INT AUTO_INCREMENT PRIMARY KEY,
  target    VARCHAR(255) NOT NULL,
  scan_date DATETIME NOT NULL,
  status    VARCHAR(50) DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  sl_no       INT,
  vuln_name   TEXT,
  severity    VARCHAR(50),
  port        VARCHAR(20),
  service     VARCHAR(100),
  description TEXT,
  FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);

CREATE TABLE IF NOT EXISTS fixes (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  sl_no    INT,
  vuln_id  INT,
  fix_text TEXT,
  source   VARCHAR(50),
  FOREIGN KEY (sl_no) REFERENCES history(sl_no),
  FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
);

CREATE TABLE IF NOT EXISTS summary (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  sl_no        INT,
  raw_scan     LONGTEXT,
  ai_analysis  LONGTEXT,
  risk_level   VARCHAR(50),
  generated_at DATETIME,
  short_summary TEXT,
  analysis_status VARCHAR(50) DEFAULT 'complete',
  analysis_error TEXT,
  FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);

CREATE TABLE IF NOT EXISTS exploit_suggestions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  sl_no INT,
  name TEXT,
  rationale TEXT,
  tool TEXT,
  safe_validation TEXT,
  FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);

CREATE TABLE IF NOT EXISTS ai_tool_calls (
  id INT AUTO_INCREMENT PRIMARY KEY,
  sl_no INT,
  call_type VARCHAR(20),
  command TEXT,
  result LONGTEXT,
  blocked BOOLEAN DEFAULT FALSE,
  FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);

-- Single-row runtime configuration (provider/model/timeouts), editable from
-- the web settings screen without restarting containers or editing .env.
CREATE TABLE IF NOT EXISTS settings (
  id               INT PRIMARY KEY DEFAULT 1,
  provider         VARCHAR(50)  DEFAULT 'ollama',
  model            VARCHAR(100) DEFAULT 'huihui_ai/qwen3.5-abliterated:9b',
  ollama_host      VARCHAR(255) DEFAULT NULL,
  api_key          VARCHAR(500) DEFAULT NULL,
  ollama_timeout   INT          DEFAULT 600,
  summary_timeout  INT          DEFAULT 120,
  scan_delay_seconds INT        DEFAULT 0,
  user_agent       VARCHAR(500) DEFAULT NULL,
  subdomain_discovery_level INT DEFAULT 0,
  updated_at       DATETIME     DEFAULT NULL
);
