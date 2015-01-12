#include "mpd_policy.h"

static int validate_xml(xmlDocPtr xml_doc) {
    int status = 0;
    xmlDocPtr schema_doc = NULL;
    xmlSchemaParserCtxtPtr parser_ctxt = NULL;
    xmlSchemaPtr schema = NULL;
    xmlSchemaValidCtxtPtr valid_ctxt = NULL;
    
    assert(xml_doc);

    if (! (schema_doc = xmlReadFile(XSD_SCHEMA_PATH, NULL, XML_PARSE_NONET))) {
        printf ("Failed to open %s file\n", XSD_SCHEMA_PATH);
        return 1;
    }

    if (! (parser_ctxt = xmlSchemaNewDocParserCtxt(schema_doc))) {
        printf ("Failed to create a parser using the schema document\n");
        status = 1;
        goto cleanup;
    }

    if (! (schema = xmlSchemaParse(parser_ctxt))) {
        status = 1;
        printf ("Failed to parse the schema\n");
        goto cleanup;
    }

    if (! (valid_ctxt = xmlSchemaNewValidCtxt(schema))) {
        status = 1;
        printf ("Failed to create the validation context\n");
        goto cleanup;
    }

    if (xmlSchemaValidateDoc(valid_ctxt, xml_doc)) {
        printf("The document is invalid\n");
        
        status = 1;
        goto cleanup;
    }

cleanup:
    if (valid_ctxt) xmlSchemaFreeValidCtxt(valid_ctxt);
    if (schema) xmlSchemaFree(schema);
    if (parser_ctxt) xmlSchemaFreeParserCtxt(parser_ctxt);
    if (schema_doc) xmlFreeDoc(schema_doc);

    return status;
}

static int write_result_to_xml(char *filename, xmlDocPtr xml_doc) {
    FILE *out;
    
    if (! (out = fopen(filename, "w")))
        return 1;
    
    /* Dump the content */
    xmlDocDump(out, xml_doc);
    
    /* Close the file */
    fclose(out);

    return 0;
}

static void remove_spaces(char *str) {
  char *p1 = str, *p2 = str;
  do
    while (*p2 == ' ')
      p2++;
  while (*p1++ = *p2++);
} 

static char *parse_attribute(xmlNode *attr_node) {
    xmlNode *it = 0;
    char *attr = 0;
    char *attr_value = 0;
    char *attr_name = 0;
    char *attr_operator = 0;
    int attr_value_len, attr_name_len, attr_operator_len;
    for (it = attr_node; it; it = it->next) {
        if (it->type == XML_ELEMENT_NODE) {
            if (strcmp((char *)it->name, ATTRIBUTE_NAME) == 0) {
                attr_name = (char *)it->last->content;
            } else if (strcmp((char *)it->name, ATTRIBUTE_VALUE) == 0) {
                attr_value = (char *)it->last->content;
            } else if (strcmp((char *)it->name, ATTRIBUTE_OPERATOR) == 0) {
                attr_operator = (char *)it->last->content;
            } else {
                printf("Invalid Node\n");
                exit(1);
            }
        }
    }
    if (!attr_value || !attr_operator || !attr_name) {
        printf("The attribute is not complete\n");
        exit(2);
    }
    
    /* Remove white spaces */
    remove_spaces(attr_value);
    remove_spaces(attr_name);
    remove_spaces(attr_operator);

    if (strcmp(attr_value, "*") != 0) {
        attr_value_len = strlen(attr_value);
        attr_operator_len = strlen(attr_operator);
        attr_name_len = strlen(attr_name);
        
        attr = malloc((attr_value_len + attr_operator_len + attr_name_len + 7) * sizeof(*attr));
        assert(attr);
        
        sprintf(attr, "%s %s %s", attr_name, attr_operator, attr_value);
        attr[attr_value_len + attr_operator_len + attr_name_len + 7] = '\0';

        return attr;
    } else {
        int attr_name_len;
        attr_name_len = strlen(attr_name);
        attr = malloc((attr_name_len + 1) * sizeof(char));
        memcpy(attr, attr_name, attr_name_len + 1);
        
        return attr;
    }
}

static char *parse_attributes_group(xmlNode *attr_group_node) {
    xmlNode *it = 0;
    char *operator_value = 0;
    char *operator_type = 0;
    xmlAttrPtr attr = 0;
    char *attr_group_str = 0;
    char *res = 0;

    attr_group_str = malloc(MAX_POLICY_LENGTH * sizeof(*attr_group_str));
    assert(attr_group_str);
    strcpy(attr_group_str, ""); 

    if (strcmp((char*)(attr_group_node->parent->name), ATTRIBUTES_GROUP) == 0) {
        for (attr = attr_group_node->parent->properties; attr ; attr = attr->next) {
            if (strcmp((char *)attr->name, XML_ATTR_OPERATOR_TYPE) == 0) {
                operator_type = (char*)attr->children->content;
            } else if (strcmp((char *)attr->name, XML_ATTR_OPERATOR_VALUE) == 0) {
                operator_value = (char*)attr->children->content;
            } else {
                printf ("Attribute %s is not a valid one\n", attr->name);
                exit(3);
            }
        }
    }

    if (operator_type && strcmp(operator_type, COMPOSITION_TYPE) == 0) {
        strcat(attr_group_str, operator_value);
        strcat(attr_group_str, " of (");
    } else {
        strcat(attr_group_str, "( ");
    }

    for (it = attr_group_node; it; it = it->next) {
        if (it->type == XML_ELEMENT_NODE) {
            if (strcmp((char *)it->name, ATTRIBUTES_GROUP) == 0) {
                res = parse_attributes_group(it->children);
            } else if (strcmp((char *)it->name, ATTRIBUTE_ELEMENT) == 0) {
                res = parse_attribute(it->children);
            } else {
                printf("BAD FORMAT\n");
                exit(1);
            }
            
            strcat(attr_group_str, res);
            free(res);

            /* Concatenate the operator */
            if (it->next && it->next->next) {
                if (operator_type && strcmp(operator_type, LOGICAL_TYPE) == 0) {
                    strcat(attr_group_str, " ");
                    if (strcmp(operator_value, "AND") == 0)
                        strcat(attr_group_str, "and");
                    else if (strcmp(operator_value, "OR") == 0)
                        strcat(attr_group_str, "or");
                    else
                        strcat(attr_group_str, operator_value);
                    strcat(attr_group_str, " ");
                } else {
                    strcat(attr_group_str, ", ");
                }
            } 
        }
    }
    
    strcat(attr_group_str, " )");

    return attr_group_str;
}

static void
parse_nodes_for_policies(xmlNodeSetPtr nodes, char ***policies, int *policies_counter) {
    int i, size;
    char *result;
    int result_len;

    size = (nodes) ? nodes->nodeNr : 0;
    *policies_counter = 0;
    
    *policies = malloc(size * sizeof(char *));
    assert(*policies);

    for(i = size - 1; i >= 0; i--) {
        assert(nodes->nodeTab[i]);
        
        xmlNode *it = NULL;
        for (it = nodes->nodeTab[i]->children; it; it = it->next) {
            if (it->type == XML_ELEMENT_NODE &&
                strcmp((char *)it->name, ATTRIBUTES_GROUP) == 0) {
                result = parse_attributes_group(it);

                result_len = strlen(result);
                (*policies)[*policies_counter] = malloc((result_len + 1) * sizeof(char));
                assert((*policies)[*policies_counter]);
                    
                strcpy((*policies)[*policies_counter], result);
                (*policies)[*policies_counter][result_len] = '\0';
                *policies_counter += 1;

                break;
            }
        }
    }
}

static int parse_policies(xmlDocPtr xml_doc, const xmlChar* xpathExpr,
                 char ***policies, int *policies_counter) {
    xmlXPathContextPtr xpathCtx; 
    xmlXPathObjectPtr xpathObj; 
    
    assert(xml_doc);
    assert(xpathExpr);

    /* Create xpath evaluation context */
    if (! (xpathCtx = xmlXPathNewContext(xml_doc))) {
        printf("Failed to create new XPath context\n"); 
        return -1;
    }
    
    /* Evaluate xpath expression */
    if (! (xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx))) {
        printf("Failed to evaluate xpath expression \"%s\"\n", xpathExpr);
        xmlXPathFreeContext(xpathCtx); 
        return -1;
    }
    
    /* Parse nodes for policies */
    parse_nodes_for_policies(xpathObj->nodesetval, policies, policies_counter);

    /* Cleanup of XPath data */
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx); 
    
    return(0);
}

static void
parse_nodes_for_files_names(xmlNodeSetPtr nodes, char ***files_names, 
                            int *files_counter) {
    int i, size, old_len;
    char *new_value;
    
    size = (nodes) ? nodes->nodeNr : 0;
    *files_counter = 0;
    
    *files_names = malloc(size * sizeof(char *));
    assert(*files_names);
    
    for(i = size - 1; i >= 0; i--) {
        assert(nodes->nodeTab[i]);
        old_len = strlen((char*) nodes->nodeTab[i]->last->content);
        
        /* Save the file name */
        (*files_names)[*files_counter] = malloc((old_len + 1) * sizeof(char));
        assert((*files_names)[*files_counter]);
        strcpy((*files_names)[*files_counter], (char*) nodes->nodeTab[i]->last->content);
        (*files_names)[*files_counter][old_len] = '\0';

        *files_counter += 1;
        
        /* Next we will change the value of the BaseURL*/
        new_value = malloc((old_len + SUFFIX_LEN + 1) * sizeof(char));
        assert(new_value);
        
        //TODO use xmlStrcat function to concatenate
        /* Concatenate "_out" to the old value */ 
        memset(new_value, 0, old_len + SUFFIX_LEN + 1);
        memcpy(new_value, (char*) nodes->nodeTab[i]->last->content, old_len);
        memcpy(new_value + old_len, SUFFIX, SUFFIX_LEN);
        new_value[old_len + SUFFIX_LEN] = '\0';

        xmlNodeSetContent(nodes->nodeTab[i], BAD_CAST new_value);
        if (nodes->nodeTab[i]->type != XML_NAMESPACE_DECL)
            nodes->nodeTab[i] = NULL;
        
        free(new_value);
    }
}

static int parse_files_names(xmlDocPtr xml_doc, const xmlChar* xpathExpr,
                 char ***files_names, int *files_counter) {
    xmlXPathContextPtr xpathCtx; 
    xmlXPathObjectPtr xpathObj; 
    
    assert(xml_doc);
    assert(xpathExpr);

    /* Create xpath evaluation context */
    if (! (xpathCtx = xmlXPathNewContext(xml_doc))) {
        printf("Failed to create new XPath context\n"); 
        return -1;
    }
    
    /* Evaluate xpath expression */
    if (! (xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx))) {
        printf("Failed to evaluate xpath expression \"%s\"\n", xpathExpr);
        xmlXPathFreeContext(xpathCtx); 
        return -1;
    }

    /* update selected nodes */
    parse_nodes_for_files_names(xpathObj->nodesetval, files_names, files_counter);

    /* Cleanup of XPath data */
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx); 
    
    return(0);
}

int parse_xml(char *xml_file, char ***policies, int *policies_counter,
                               char ***files_names, int *files_counter)
{
    xmlDocPtr xml_doc;
    
    if (! (xml_doc = xmlReadFile(xml_file, NULL, XML_PARSE_NONET))) {
        printf ("Failed to open %s file\n", xml_file);
        return 1;
    }

    /* Parse the document and get the attributes groups*/
    parse_policies(xml_doc, BAD_CAST ATTRIBUTES_ROOT, policies, policies_counter);
    
    /* Parse the document and change the values from BaseURL elements */
    parse_files_names(xml_doc, BAD_CAST BASEURL_XPATH, files_names, files_counter);

    xmlFreeDoc(xml_doc);

    return 0;    
}
