// Keeps asynchronous detail responses scoped to the currently selected review.
export function createIncidentReviewRequestGuard() {
  let selectedReviewId = null
  let generation = 0

  return {
    select(reviewId) {
      selectedReviewId = reviewId
      generation += 1
    },
    selectAndBegin(reviewId) {
      this.select(reviewId)
      return this.begin(reviewId)
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

export function createOperationsRequestGuard() {
  const generations = new Map()
  return {
    begin(resource) {
      const generation = (generations.get(resource) ?? 0) + 1
      generations.set(resource, generation)
      return generation
    },
    invalidate(resource) {
      generations.set(resource, (generations.get(resource) ?? 0) + 1)
    },
    isCurrent(resource, generation) {
      return generations.get(resource) === generation
    },
  }
}
