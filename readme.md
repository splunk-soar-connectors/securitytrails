[comment]: # "Auto-generated SOAR connector documentation"
# SecurityTrails

Publisher: Domenico Perre  
Connector Version: 1\.1\.0  
Product Vendor: SecurityTrails  
Product Name: API  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.2\.7532  

This action supports investigate actions to provide interface to SecurityTrails API

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a API asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | Base URL for API request
**api\_key** |  required  | password | API Key for connectivity

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using the supplied configuration  
[lookup domain](#action-lookup-domain) - Check for the presence of a domain in a threat intelligence feed  
[whois domain](#action-whois-domain) - Execute whois lookup on the given domain  
[whois history](#action-whois-history) - Obtain historic whois records for a domain name  
[domain searcher](#action-domain-searcher) - Filter and search specific records using this endpoint  
[domain category](#action-domain-category) - Returns tags for a given domain  
[domain subdomain](#action-domain-subdomain) - Returns subdomains for a given domain  
[domain history](#action-domain-history) - Lists out specific historical information about the given domain parameter  

## action: 'test connectivity'
Validate the asset configuration for connectivity using the supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup domain'
Check for the presence of a domain in a threat intelligence feed

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to lookup | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.a\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.a\.\*\.type | string | 
action\_result\.data\.\*\.aaaa\.\*\.ipv6 | string |  `ipv6` 
action\_result\.data\.\*\.aaaa\.\*\.type | string | 
action\_result\.data\.\*\.alexa\_rank | numeric | 
action\_result\.data\.\*\.hostname | string |  `host name` 
action\_result\.summary\.domain | string |  `domain` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'whois domain'
Execute whois lookup on the given domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.contacts\.\*\.city | string | 
action\_result\.data\.\*\.contacts\.\*\.countryCode | string | 
action\_result\.data\.\*\.contacts\.\*\.email | string |  `email` 
action\_result\.data\.\*\.contacts\.\*\.fax | string |  `fax` 
action\_result\.data\.\*\.contacts\.\*\.name | string |  `name` 
action\_result\.data\.\*\.contacts\.\*\.organization | string | 
action\_result\.data\.\*\.contacts\.\*\.state | string | 
action\_result\.data\.\*\.contacts\.\*\.street1 | string |  `street` 
action\_result\.data\.\*\.contacts\.\*\.telephone | string |  `telephone` 
action\_result\.data\.\*\.contacts\.\*\.type | string | 
action\_result\.summary\.domain | string |  `domain` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'whois history'
Obtain historic whois records for a domain name

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.result\.items\.\*\.contact\.\*\.city | string | 
action\_result\.data\.\*\.result\.items\.\*\.contact\.\*\.countryCode | string | 
action\_result\.data\.\*\.result\.items\.\*\.contact\.\*\.email | string |  `email` 
action\_result\.data\.\*\.result\.items\.\*\.contact\.\*\.fax | string |  `fax` 
action\_result\.data\.\*\.result\.items\.\*\.contact\.\*\.name | string |  `name` 
action\_result\.data\.\*\.result\.items\.\*\.contact\.\*\.organization | string | 
action\_result\.data\.\*\.result\.items\.\*\.contact\.\*\.state | string | 
action\_result\.data\.\*\.result\.items\.\*\.contact\.\*\.street1 | string |  `street` 
action\_result\.data\.\*\.result\.items\.\*\.contact\.\*\.telephone | string |  `telephone` 
action\_result\.data\.\*\.result\.items\.\*\.contact\.\*\.type | string | 
action\_result\.summary\.domain | string |  `domain` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'domain searcher'
Filter and search specific records using this endpoint

Type: **investigate**  
Read only: **True**

Using simple filter composition, any type of data fetching is possible\. The post object uses a very simple DSL where the json key represents the type to filter on and the value\. Given this, you can create any number of queries, depending on the need\. <b>Filter</b> parameter is used to specify what type of record you want to search against\. <b>Filter string</b> parameter is used to provide a string value e\.g\. if you selected apex\_domain in filter, you can enter a domain value that you want to search in this panel\. <b>Keyword</b> parameter is optional e\.g\. if you select 'mx' as the filter and 'alt4\.aspmx\.l\.google\.com' as the filterstring you could type 'stackover' to retrieve all mx records related to stackoverflow\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**filter** |  required  | Type of record you want to search against | string | 
**filterstring** |  required  | Filter string to search | string | 
**keyword** |  optional  | Keyword to search corresponding filter results | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.filter | string | 
action\_result\.parameter\.filterstring | string | 
action\_result\.parameter\.keyword | string | 
action\_result\.data\.\*\.records\.\*\.alexa\_rank | numeric | 
action\_result\.data\.\*\.records\.\*\.hostname | string |  `domain` 
action\_result\.summary\.domain | string |  `domain` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'domain category'
Returns tags for a given domain

Type: **investigate**  
Read only: **True**

Returns tags such as gambling, sports, news\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to be queried | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.tags | string | 
action\_result\.summary\.domain | string |  `domain` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'domain subdomain'
Returns subdomains for a given domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to be queried | string |  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.data\.\*\.\*\.domain | string |  `domain` 
action\_result\.summary\.domain | string |  `domain` 
action\_result\.summary\.domain | string |  `domain` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'domain history'
Lists out specific historical information about the given domain parameter

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to be queried | string |  `domain` 
**record\_type** |  required  | DNS record type | string |  `\*` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain` 
action\_result\.parameter\.record\_type | string |  `\*` 
action\_result\.data\.\*\.results\.\*\.first\_seen | string |  `date` 
action\_result\.data\.\*\.results\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.results\.\*\.last\_seen | string |  `date` 
action\_result\.data\.\*\.results\.\*\.organizations | string | 
action\_result\.summary\.domain | string |  `domain` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 