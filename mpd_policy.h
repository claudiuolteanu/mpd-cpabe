#ifndef MPD_POLICY_H_
#define MPD_POLICY_H_   1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <libxml/parser.h>
#include <libxml/xmlschemas.h>
#include <libxml/valid.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#define LOGICAL_TYPE        "Logical"
#define COMPOSITION_TYPE    "Composition"

#define OPERATOR_AND        "AND"
#define OPERATOR_OR         "OR"

#define XML_ATTR_OPERATOR_VALUE    "OperatorValue"
#define XML_ATTR_OPERATOR_TYPE     "OperatorType"

#define ATTRIBUTES_GROUP    "AttributesGroup"
#define ATTRIBUTE_ELEMENT   "Attribute"
#define ATTRIBUTE_NAME      "Name"
#define ATTRIBUTE_VALUE     "Value"
#define ATTRIBUTE_OPERATOR  "Operator"

#define ATTRIBUTES_ROOT     "//*[name()='Representation']"

#define MAX_POLICY_LENGTH   1024

#define FILE_EXTENSION      ".mpd"
#define SUFFIX              "_out"
#define SUFFIX_LEN          4
#define BASEURL_XPATH       "//*[name()='BaseURL']"
#define XSD_SCHEMA_PATH     "DASH-MPD.xsd"
#define VALIDATE_XML        1

int parse_xml(char *xml_file, char ***policies, int *policies_counter, 
                               char ***files_names, int *files_counter);

#endif
