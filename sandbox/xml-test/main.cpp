//
// Created by muman on 11/18/18.
//

#include <cstring>
#include <cerrno>
#include <cassert>
#include <iostream>

#include <libxml/parser.h>
#include <libxml/tree.h>

using namespace std;

const string db_path = "../../../db/db.xml";


/**
 * Retrieve <response> child node text content for username/password pair.
 *
 * @param doc
 * @param root
 * @param name
 * @param pass
 * @param response
 * @return
 */
static bool get_response_from_xml(xmlDocPtr doc, xmlNodePtr root, const string & name,
        const string & pass, string & response)
{
    xmlNodePtr thisNode = root->children;

    while (thisNode) {
        if ((thisNode->type == XML_ELEMENT_NODE) && (xmlStrcasecmp(thisNode->name, BAD_CAST "user") == 0)) {
            string user_name, user_password;
            xmlNodePtr response_node = nullptr;

            xmlNodePtr subNode = thisNode->children;

            while (subNode) {
                if (subNode->type == XML_ELEMENT_NODE) {
                    if (xmlStrcasecmp(subNode->name, BAD_CAST "name") == 0) {
                        user_name = (const char *)xmlNodeGetContent(subNode->children);
                    } else if (xmlStrcasecmp(subNode->name, BAD_CAST "password") == 0) {
                        user_password = (const char *)xmlNodeGetContent(subNode->children);
                    } else if (xmlStrcasecmp(subNode->name, BAD_CAST "response") == 0) {
                        response_node = subNode->children->next;
                    } else {
                        break;
                    }
                }

                subNode = subNode->next;
            }

            if ((user_name == name) && (user_password == pass) && (response_node != nullptr)) {
                xmlBufferPtr buf = xmlBufferCreate();

                if (xmlNodeDump(buf, doc, response_node, 4, 1) != -1) {
                    response = (const char *) buf->content;
                    return true;
                }
            }
        }

        thisNode = thisNode->next;
    }
}

static bool get_response_for_user(const string & dbpath, const string & user, const string & pass, string & resp) {
    xmlDocPtr doc = nullptr;

    doc = xmlParseFile(dbpath.c_str());
    if (doc) {
        xmlNodePtr rootNode = xmlDocGetRootElement(doc);
        if (rootNode) {
            return get_response_from_xml(doc, rootNode, user, pass, resp);
        } else {

        }
    } else {

    }

    return false;
}

int main(int argc, char * argv[]) {
    // Make sure user name is passed as argv[1]
    if (argc != 3) {
        cout << argv[0] << " [User Name] [Password]\n";
        return 1;
    }

    string username = argv[1];
    string password = argv[2];
    string resp;

    if (get_response_for_user(db_path, username, password, resp)) {
        cout << resp << "\n";
    }

    return 0;
}