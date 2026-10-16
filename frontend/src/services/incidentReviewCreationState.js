export function createIncidentReviewAttemptGuard() {
  let generation = 0
  let submitting = false

  return {
    begin(selectionVersion) {
      if (submitting) return null
      submitting = true
      generation += 1
      return { generation, selectionVersion }
    },
    isCurrent(attempt) {
      return Boolean(attempt) && submitting && attempt.generation === generation
    },
    maySelectCreatedReview(attempt, currentSelectionVersion) {
      return this.isCurrent(attempt) && attempt.selectionVersion === currentSelectionVersion
    },
    finish(attempt) {
      if (!this.isCurrent(attempt)) return false
      submitting = false
      return true
    },
    invalidate() {
      generation += 1
      submitting = false
    },
  }
}

export function createIncidentReviewListGuard() {
  let generation = 0
  return {
    begin() {
      generation += 1
      return generation
    },
    invalidate() {
      generation += 1
    },
    isCurrent(request) {
      return request === generation
    },
  }
}

export function upsertCreatedIncidentReview(reviews, review) {
  return [review, ...reviews.filter((item) => item.id !== review.id)]
}

export function completeCreatedIncidentReview({
  review,
  attempt,
  currentSelectionVersion,
  requestGuard,
  onSelectReview,
  setSelectedReview,
  refreshOperations,
}) {
  const shouldSelect = attempt.selectionVersion === currentSelectionVersion
  if (shouldSelect) {
    requestGuard.select(review.id)
    setSelectedReview(review)
    onSelectReview?.(review.id)
  }
  refreshOperations?.()
  return shouldSelect
}
