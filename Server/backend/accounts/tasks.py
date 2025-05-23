from celery import shared_task
from django.utils import timezone
from django.db.models import Count
from .models import LogEntry
import numpy as np
from scipy.stats import gaussian_kde
from math import log2
import logging

logger = logging.getLogger(__name__)

@shared_task
def detect_anomalies(user_id, start_time, end_time, client_id=None):
    """
    Celery task to detect anomalies in LogEntry records using entropy and density-based methods.
    Args:
        user_id: ID of the User to analyze logs for.
        start_time: Start of the time window (ISO format string).
        end_time: End of the time window (ISO format string).
        client_id: Optional Client ID to filter logs by specific client.
    """
    try:
        # Convert ISO strings to datetime
        start_time = timezone.datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        end_time = timezone.datetime.fromisoformat(end_time.replace('Z', '+00:00'))

        # Fetch logs for the user and optional client
        query = LogEntry.objects.filter(user_id=user_id, timestamp__range=(start_time, end_time))
        if client_id:
            query = query.filter(client_id=client_id)
        logs = query.order_by('timestamp')

        if not logs.exists():
            logger.info(f"No logs found for user_id={user_id}, client_id={client_id}")
            return {'status': 'no_logs', 'processed': 0}

        # Entropy-based anomaly detection
        entropy_score = calculate_entropy(logs)
        entropy_threshold = 1.0  # Example threshold (adjust based on data)

        # Density-based anomaly detection
        density_scores = calculate_density(logs)
        density_threshold = np.percentile(density_scores, 95) if density_scores else 0

        # Update logs with anomaly scores
        updated_logs = 0
        for log, density_score in zip(logs, density_scores):
            # Combine entropy and density scores (e.g., weighted average)
            anomaly_score = (0.5 * (entropy_score < entropy_threshold) + 0.5 * (density_score > density_threshold))
            if anomaly_score > 0:
                log.anomaly_score = anomaly_score
                log.save(update_fields=['anomaly_score'])
                updated_logs += 1

        logger.info(f"Processed {len(logs)} logs for user_id={user_id}, flagged {updated_logs} anomalies")
        return {'status': 'success', 'processed': len(logs), 'flagged': updated_logs}

    except Exception as e:
        logger.error(f"Anomaly detection failed: {str(e)}")
        return {'status': 'error', 'message': str(e)}

def calculate_entropy(logs):
    """
    Calculate Shannon entropy based on event_type distribution.
    Low entropy indicates unusual patterns (e.g., repeated failed logins).
    """
    total = logs.count()
    if total == 0:
        return 0
    event_counts = logs.values('event_type').annotate(count=Count('event_type'))
    entropy = -sum((item['count'] / total) * log2(item['count'] / total) for item in event_counts)
    return entropy

def calculate_density(logs):
    """
    Calculate density-based anomaly scores using a Gaussian kernel density estimator.
    High density indicates potential anomalies (e.g., rapid event clusters).
    """
    timestamps = np.array([log.timestamp.timestamp() for log in logs])
    if len(timestamps) < 2:
        return []
    try:
        kde = gaussian_kde(timestamps, bw_method='silverman')
        density_scores = kde(timestamps)
        return density_scores
    except np.linalg.LinAlgError:
        logger.warning("Density calculation failed; insufficient data variation")
        return [0] * len(timestamps)


