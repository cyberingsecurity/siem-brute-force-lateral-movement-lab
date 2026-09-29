# Detection rules

These lab-specific event detections are written in Sigma YAML and use normalized fields emitted by the local SIEM exercise. They are marked `status: test`; map fields and log sources to the target platform, then validate against representative telemetry before deployment.

Threshold, time-window, and grouping behavior for the app-native rules is documented in the corresponding investigation reports. Preview results are recorded separately from post-replay alerts so an unobserved live alert is not presented as validated coverage.
