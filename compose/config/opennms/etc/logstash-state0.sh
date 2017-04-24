#!/bin/bash
../bin/send-event.pl uei.opennms.org/enterprise/logstash/generic/state/0 \
	--parm 'Description Logststash test error log' \
	--parm 'Hostname lx1' \
	--parm 'Message Logstash test error log' \
	--parm 'Origin logstash' \
	--parm 'Type auto' \
	--parm "EventId 69" \
	--parm 'OperInstruct https://www.elastic.co/products/logstash' \
	--parm 'IncidentMessage Logstash test error log' \
	--parm 'SubSource X-X-X' \
	--parm 'Source X-X-X' \
	--parm 'Component X-X-X' \
	--parm 'Collection 0' \
	--parm 'ITService Business_Transaction' \
	--parm 'TicketOwner Operator' \
	--parm 'TicketPriority	4' \
	-x 3 
