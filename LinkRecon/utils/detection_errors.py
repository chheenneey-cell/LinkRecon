"""Detector errors must reach the scan outcome, not only a log file."""
def report_detection_error(config, detector, source, error):
    callback = getattr(config, 'record_detection_error', None)
    if callable(callback):
        callback(f'{source or config.target or "unknown"} [{detector}]: {error}')
