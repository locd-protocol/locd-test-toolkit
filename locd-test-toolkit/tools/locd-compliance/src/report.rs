//! Report generation with HTML templates

use serde::Serialize;

#[derive(Serialize)]
pub struct ComplianceReport {
    pub protocol_version: String,
    pub report_date: String,
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub pass_rate: f64,
    pub test_suites: Vec<TestSuite>,
}

#[derive(Serialize)]
pub struct TestSuite {
    pub name: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub tests: Vec<TestResult>,
}

#[derive(Serialize)]
pub struct TestResult {
    pub name: String,
    pub status: TestStatus,
    pub duration: String,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub enum TestStatus {
    Pass,
    Fail,
}

impl ComplianceReport {
    pub fn new() -> Self {
        Self {
            protocol_version: locd_core::PROTOCOL_VERSION.to_string(),
            report_date: chrono::Utc::now()
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string(),
            total_tests: 0,
            passed: 0,
            failed: 0,
            pass_rate: 0.0,
            test_suites: Vec::new(),
        }
    }

    pub fn add_suite(&mut self, suite: TestSuite) {
        self.total_tests += suite.total;
        self.passed += suite.passed;
        self.failed += suite.failed;
        self.test_suites.push(suite);

        if self.total_tests > 0 {
            self.pass_rate = (self.passed as f64 / self.total_tests as f64) * 100.0;
        }
    }

    pub fn to_html(&self) -> Result<String, anyhow::Error> {
        let mut tera = tera::Tera::default();
        tera.add_raw_template("report", REPORT_TEMPLATE)?;

        let context = tera::Context::from_serialize(self)?;
        Ok(tera.render("report", &context)?)
    }
}

const REPORT_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Loc'd Protocol Compliance Report</title>
    <meta charset="utf-8">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .metric {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .metric.success { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }
        .metric.warning { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
        .metric h3 {
            margin: 0 0 10px 0;
            font-size: 14px;
            text-transform: uppercase;
            opacity: 0.9;
        }
        .metric .value {
            font-size: 36px;
            font-weight: bold;
            margin: 0;
        }
        .suite {
            margin: 30px 0;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }
        .suite-header {
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #e0e0e0;
        }
        .suite-header h2 {
            margin: 0;
            font-size: 18px;
            color: #2c3e50;
        }
        .suite-stats {
            font-size: 14px;
            color: #7f8c8d;
            margin-top: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th {
            background: #ecf0f1;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #2c3e50;
            border-bottom: 2px solid #bdc3c7;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #ecf0f1;
        }
        .status-pass {
            color: #27ae60;
            font-weight: 600;
        }
        .status-fail {
            color: #e74c3c;
            font-weight: 600;
        }
        .error {
            color: #e74c3c;
            font-size: 12px;
            font-family: monospace;
            background: #fef5f5;
            padding: 5px;
            border-radius: 3px;
            margin-top: 5px;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            text-align: center;
            color: #7f8c8d;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Loc'd Protocol Compliance Report</h1>

        <div class="meta">
            <p><strong>Protocol Version:</strong> {{ protocol_version }}</p>
            <p><strong>Generated:</strong> {{ report_date }}</p>
        </div>

        <div class="summary">
            <div class="metric">
                <h3>Total Tests</h3>
                <p class="value">{{ total_tests }}</p>
            </div>
            <div class="metric success">
                <h3>Passed</h3>
                <p class="value">{{ passed }}</p>
            </div>
            <div class="metric {% if failed > 0 %}warning{% else %}success{% endif %}">
                <h3>Failed</h3>
                <p class="value">{{ failed }}</p>
            </div>
            <div class="metric {% if pass_rate >= 80 %}success{% else %}warning{% endif %}">
                <h3>Pass Rate</h3>
                <p class="value">{{ pass_rate | round(precision=1) }}%</p>
            </div>
        </div>

        {% for suite in test_suites %}
        <div class="suite">
            <div class="suite-header">
                <h2>{{ suite.name }}</h2>
                <div class="suite-stats">
                    {{ suite.passed }}/{{ suite.total }} tests passed
                    {% if suite.failed > 0 %}
                        <span style="color: #e74c3c;">({{ suite.failed }} failed)</span>
                    {% endif %}
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Test</th>
                        <th>Status</th>
                        <th>Duration</th>
                    </tr>
                </thead>
                <tbody>
                    {% for test in suite.tests %}
                    <tr>
                        <td>
                            {{ test.name }}
                            {% if test.error %}
                            <div class="error">{{ test.error }}</div>
                            {% endif %}
                        </td>
                        <td class="status-{{ test.status | lower }}">
                            {% if test.status == "Pass" %}✓ PASS{% else %}✗ FAIL{% endif %}
                        </td>
                        <td>{{ test.duration }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endfor %}

        <div class="footer">
            <p>Generated by Loc'd Protocol Test Toolkit</p>
            <p>Repository: <a href="https://github.com/locd-protocol/locd-test-toolkit">github.com/locd-protocol/locd-test-toolkit</a></p>
        </div>
    </div>
</body>
</html>
"#;
