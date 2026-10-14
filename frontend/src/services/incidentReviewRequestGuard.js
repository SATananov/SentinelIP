// Keeps asynchronous detail responses scoped to the currently selected review.
export function createIncidentReviewRequestGuard() {
  let selectedReviewId = null
  let generation = 0

  return {
    select(reviewId) {
      selectedReviewId = reviewId
      generation += 1
    },
    invalidate() {
      selectedReviewId = null
      generation += 1
    },
    begin(reviewId) {
      generation += 1
      return { reviewId, generation }
    },
    isCurrent(request) {
      return request.reviewId === selectedReviewId && request.generation === generation
    },
  }
}
