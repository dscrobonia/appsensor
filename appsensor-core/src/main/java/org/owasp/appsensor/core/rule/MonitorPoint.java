package org.owasp.appsensor.core.rule;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.owasp.appsensor.core.DetectionPoint;

/**
 * A MonitorPoint is a DetectionPoint that does not generate attacks,
 * but is rather a component of a Rule which generates attacks.
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 */
public class MonitorPoint extends DetectionPoint {
	public MonitorPoint () { }

	public MonitorPoint(DetectionPoint detectionPoint) {
		super(detectionPoint.getCategory(),
				detectionPoint.getLabel(),
				detectionPoint.getThreshold(),
				detectionPoint.getResponses(),
				detectionPoint.getGuid());
	}

	public MonitorPoint(DetectionPoint detectionPoint, String guid) {
		super(detectionPoint.getCategory(),
				detectionPoint.getLabel(),
				detectionPoint.getThreshold(),
				detectionPoint.getResponses(),
				guid);
	}
}