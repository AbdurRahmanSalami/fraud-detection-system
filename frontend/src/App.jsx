import { useState } from "react";
import axios from "axios";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  LoaderCircle,
  Mail,
  RotateCcw,
  Search,
  ShieldCheck,
} from "lucide-react";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

const phishingExample =
  "Urgent! Your bank account has been suspended. Click the link immediately and confirm your password to restore access.";

const safeExample =
  "Hello, the project meeting has been moved to 10:00 AM tomorrow. Please review the attached agenda before the meeting.";

function MetricCard({ label, value, description }) {
  return (
    <article className="metric-card">
      <p>{label}</p>
      <strong>{value}</strong>
      <span>{description}</span>
    </article>
  );
}

function ProbabilityBar({ label, value }) {
  const percentage = Math.min(Math.max(value * 100, 0), 100);

  return (
    <div className="probability">
      <div className="probability-heading">
        <span>{label}</span>
        <strong>{percentage.toFixed(2)}%</strong>
      </div>

      <div className="probability-track">
        <div
          className="probability-fill"
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
}

function App() {
  const [emailText, setEmailText] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const analyseEmail = async (event) => {
    event.preventDefault();

    const cleanedText = emailText.trim();

    if (!cleanedText) {
      setError("Enter or paste an email before analysing it.");
      setResult(null);
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await axios.post(`${API_URL}/predict`, {
        text: cleanedText,
      });

      setResult(response.data);
    } catch (requestError) {
      console.error(requestError);

      const message =
        requestError.response?.data?.detail ||
        "The application could not reach the prediction server. Confirm that FastAPI is running.";

      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const loadExample = (example) => {
    setEmailText(example);
    setResult(null);
    setError("");
  };

  const clearForm = () => {
    setEmailText("");
    setResult(null);
    setError("");
  };

  const resultClass = result?.is_phishing
    ? "result-card phishing-result"
    : "result-card safe-result";

  return (
    <main className="page">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={27} />
          </div>

          <div>
            <h1>FraudGuard AI</h1>
            <p>Phishing email detection system</p>
          </div>
        </div>

        <div className="status-badge">
          <span />
          Model online
        </div>
      </header>

      <section className="hero">
        <div>
          <p className="eyebrow">AI-POWERED EMAIL SECURITY</p>
          <h2>Detect suspicious emails before they cause harm.</h2>
          <p className="hero-description">
            Paste an email into the analyser to estimate whether it is a safe
            message or a potential phishing attempt.
          </p>
        </div>

        <div className="hero-icon">
          <Mail size={55} />
        </div>
      </section>

      <section className="metrics-grid">
        <MetricCard
          label="Test accuracy"
          value="98.52%"
          description="Overall correct predictions"
        />

        <MetricCard
          label="Phishing recall"
          value="98.07%"
          description="Phishing emails detected"
        />

        <MetricCard
          label="ROC AUC"
          value="99.76%"
          description="Class-separation performance"
        />
      </section>

      <section className="workspace">
        <form className="analyser-card" onSubmit={analyseEmail}>
          <div className="section-heading">
            <div>
              <p className="section-label">EMAIL ANALYSER</p>
              <h3>Analyse an email</h3>
            </div>

            <Activity size={24} />
          </div>

          <label htmlFor="email-text">Email content</label>

          <textarea
            id="email-text"
            value={emailText}
            onChange={(event) => setEmailText(event.target.value)}
            placeholder="Paste the subject and body of the email here..."
            maxLength={100000}
          />

          <div className="text-information">
            <span>{emailText.length.toLocaleString()} characters</span>
            <span>Do not enter passwords or private credentials.</span>
          </div>

          <div className="example-buttons">
            <button
              type="button"
              className="secondary-button"
              onClick={() => loadExample(phishingExample)}
            >
              Load phishing example
            </button>

            <button
              type="button"
              className="secondary-button"
              onClick={() => loadExample(safeExample)}
            >
              Load safe example
            </button>
          </div>

          {error && (
            <div className="error-message">
              <AlertTriangle size={18} />
              <span>{error}</span>
            </div>
          )}

          <div className="form-actions">
            <button
              type="button"
              className="clear-button"
              onClick={clearForm}
              disabled={loading}
            >
              <RotateCcw size={18} />
              Clear
            </button>

            <button
              type="submit"
              className="analyse-button"
              disabled={loading || !emailText.trim()}
            >
              {loading ? (
                <>
                  <LoaderCircle className="spinner" size={19} />
                  Analysing
                </>
              ) : (
                <>
                  <Search size={19} />
                  Analyse email
                </>
              )}
            </button>
          </div>
        </form>

        <section className="results-section">
          {!result ? (
            <div className="empty-result">
              <div>
                <Search size={34} />
              </div>
              <h3>No analysis yet</h3>
              <p>
                Enter an email and select “Analyse email” to display the
                prediction.
              </p>
            </div>
          ) : (
            <article className={resultClass}>
              <div className="result-heading">
                <div
                  className={
                    result.is_phishing
                      ? "result-icon warning-icon"
                      : "result-icon success-icon"
                  }
                >
                  {result.is_phishing ? (
                    <AlertTriangle size={28} />
                  ) : (
                    <CheckCircle2 size={28} />
                  )}
                </div>

                <div>
                  <p>Prediction</p>
                  <h3>{result.label}</h3>
                </div>

                <span className="risk-badge">
                  {result.risk_level} risk
                </span>
              </div>

              <div className="probability-list">
                <ProbabilityBar
                  label="Phishing probability"
                  value={result.phishing_probability}
                />

                <ProbabilityBar
                  label="Safe probability"
                  value={result.safe_probability}
                />
              </div>

              <div className="result-details">
                <div>
                  <span>Confidence</span>
                  <strong>{result.confidence_percentage}%</strong>
                </div>

                <div>
                  <span>Model threshold</span>
                  <strong>{result.classification_threshold}</strong>
                </div>

                <div>
                  <span>Characters analysed</span>
                  <strong>
                    {result.characters_analysed.toLocaleString()}
                  </strong>
                </div>
              </div>

              <p className="result-note">
                This prediction is produced by a machine-learning model and
                should support, rather than replace, human judgement.
              </p>
            </article>
          )}
        </section>
      </section>
    </main>
  );
}

export default App;
