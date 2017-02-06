package org.owasp.appsensor.storage.elasticsearch.dao;

import com.fasterxml.jackson.core.JsonProcessingException;

import org.elasticsearch.index.query.BoolQueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.rule.Rule;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.util.List;

/**
 * This is a repository/dao class for storing/retrieving {@link Event} objects
 *
 * @author Maik Jäkel(m.jaekel@xsite.de) http://www.xsite.de
 */

@Repository
public class EventRepository extends AbstractElasticRepository {

    private static final String ELASTIC_TYPE = "event";


    public void save(Event event) throws JsonProcessingException {
        super.save(event);
    }


    public List<Event> findEventsBySearchCriteria(SearchCriteria criteria) throws IOException {
    	Rule rule = criteria.getRule();
    	criteria.setRule(null);

    	BoolQueryBuilder query = convertSearchCriteriaToQueryBuilder(criteria);

    	if (rule !=  null) {
    		for (DetectionPoint detectionPoint : rule.getAllDetectionPoints()) {
    			query.should(buildDetectionPointBoolQuery(QueryBuilders.boolQuery(), detectionPoint));
    		}
    	}

        return findByQueryBuilder(query, Event.class);
    }

    @Override
    protected String getElasticIndexType() {
        return ELASTIC_TYPE;
    }
}
