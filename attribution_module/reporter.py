import os
from jinja2 import Environment, FileSystemLoader

DEFAULT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>MalScan Report - {{ job_id }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .verdict-Malicious { color: red; font-weight: bold; }
        .verdict-Suspicious { color: orange; font-weight: bold; }
        .verdict-Clear { color: green; font-weight: bold; }
        .card { border: 1px solid #ccc; padding: 20px; margin-bottom: 20px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>MalScan Report</h1>
    <p>Job ID: {{ job_id }}</p>

    <div class="card">
        <h2>Verdict: <span class="verdict-{{ score_data.verdict }}">{{ score_data.verdict }}</span></h2>
        <p><strong>Confidence Score:</strong> {{ score_data.score }} / 100</p>
        
        <h3>Reasons:</h3>
        <ul>
            {% for reason in score_data.reasons %}
                <li>{{ reason }}</li>
            {% endfor %}
            {% if not score_data.reasons %}
                <li>No suspicious indicators found.</li>
            {% endif %}
        </ul>
    </div>

    <div class="card">
        <h2>Extracted Data Summary</h2>
        <pre>{{ raw_data | tojson(indent=2) }}</pre>
    </div>
</body>
</html>
"""

def generate_report(job_id: str, score_data: dict, raw_data: dict, output_dir: str = "/tmp") -> str:
    """
    Generates a standalone HTML report for a scanned job.
    Uses a default inline Jinja template if no file is provided.
    """
    from jinja2 import Template
    
    template = Template(DEFAULT_TEMPLATE)
    html_content = template.render(
        job_id=job_id,
        score_data=score_data,
        raw_data=raw_data
    )
    
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, f"report_{job_id}.html")
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    return report_path
