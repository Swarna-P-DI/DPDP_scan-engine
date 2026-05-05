import { useState } from "react";

export default function Reviewer() {
  const [comment, setComment] = useState("");
  const [reviewStatus, setReviewStatus] = useState("approved");
  const [submitted, setSubmitted] = useState(false);

  const submitReview = () => {
    setSubmitted(true);
  };

  return (
    <section className="panel panel-wide">
      <div className="panel-header">
        <div>
          <h2>Review</h2>
          <p>Record a local reviewer decision for this run.</p>
        </div>
      </div>

      <div className="segmented-control">
        <button
          className={reviewStatus === "approved" ? "active" : ""}
          onClick={() => setReviewStatus("approved")}
        >
          Approve
        </button>
        <button
          className={reviewStatus === "rejected" ? "active" : ""}
          onClick={() => setReviewStatus("rejected")}
        >
          Reject
        </button>
      </div>

      <textarea
        onChange={(event) => {
          setComment(event.target.value);
          setSubmitted(false);
        }}
        placeholder="Reviewer comments"
        value={comment}
      />

      <button className="secondary-action" onClick={submitReview}>Submit Review</button>
      {submitted && <p className="review-note">Review marked as {reviewStatus}.</p>}
    </section>
  );
}
