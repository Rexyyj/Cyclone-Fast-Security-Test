#include "dds/dds.h"
#include "HelloWorldData.h"
#include <stdio.h>
#include <stdlib.h>

int main (int argc, char ** argv)
{
  dds_entity_t participant;
  dds_entity_t topic;
  dds_entity_t writer;
  dds_return_t rc;
  HelloWorldData_Msg msg;
  uint32_t status = 0;
  (void)argc;
  (void)argv;
  dds_qos_t *qos_sec;
  qos_sec=dds_create_qos ();
  dds_qset_prop(qos_sec, "dds.sec.auth.library.path", "dds_security_auth");
  dds_qset_prop(qos_sec, "dds.sec.auth.library.init", "init_authentication");
  dds_qset_prop(qos_sec, "dds.sec.auth.library.finalize", "finalize_authentication");
  dds_qset_prop(qos_sec, "dds.sec.auth.identity_ca", "file://certs/maincacert.pem");
  dds_qset_prop(qos_sec, "dds.sec.auth.private_key", "file://certs/mainpubkey.pem");
  dds_qset_prop(qos_sec, "dds.sec.auth.identity_certificate", "file://certs/mainpubcert.pem");

  dds_qset_prop(qos_sec, "dds.sec.crypto.library.path", "dds_security_crypto");
  dds_qset_prop(qos_sec, "dds.sec.crypto.library.init", "init_crypto");
  dds_qset_prop(qos_sec, "dds.sec.crypto.library.finalize", "finalize_crypto");

  dds_qset_prop(qos_sec, "dds.sec.access.library.path", "dds_security_ac");
  dds_qset_prop(qos_sec, "dds.sec.access.library.init", "init_access_control");
  dds_qset_prop(qos_sec, "dds.sec.access.library.finalize", "finalize_access_control");
  dds_qset_prop(qos_sec, "dds.sec.access.permissions_ca", "file://certs/maincacert.pem");
  dds_qset_prop(qos_sec, "dds.sec.access.governance", "file://certs/governance.smime");
  dds_qset_prop(qos_sec, "dds.sec.access.permissions", "file://certs/permissions.smime");
  /* Create a Participant. */
  participant = dds_create_participant (0, qos_sec, NULL);
  dds_delete_qos(qos_sec);
  if (participant < 0)
    DDS_FATAL("dds_create_participant: %s\n", dds_strretcode(-participant));

  /* Create a Topic. */
  topic = dds_create_topic (
    participant, &HelloWorldData_Msg_desc, "HelloWorldData_Msg", NULL, NULL);
  if (topic < 0)
    DDS_FATAL("dds_create_topic: %s\n", dds_strretcode(-topic));

  /* Create a Writer. */
  writer = dds_create_writer (participant, topic, NULL, NULL);
  if (writer < 0)
    DDS_FATAL("dds_create_writer: %s\n", dds_strretcode(-writer));

  printf("=== [Publisher]  Waiting for a reader to be discovered ...\n");
  fflush (stdout);

  rc = dds_set_status_mask(writer, DDS_PUBLICATION_MATCHED_STATUS);
  if (rc != DDS_RETCODE_OK)
    DDS_FATAL("dds_set_status_mask: %s\n", dds_strretcode(-rc));

  while(!(status & DDS_PUBLICATION_MATCHED_STATUS))
  {
    rc = dds_get_status_changes (writer, &status);
    if (rc != DDS_RETCODE_OK)
      DDS_FATAL("dds_get_status_changes: %s\n", dds_strretcode(-rc));

    /* Polling sleep. */
    dds_sleepfor (DDS_MSECS (20));
  }

  /* Create a message to write. */
  msg.userID = 1;
  msg.message = "Hello World";

  printf ("=== [Publisher]  Writing : ");
  printf ("Message (%"PRId32", %s)\n", msg.userID, msg.message);
  fflush (stdout);

  rc = dds_write (writer, &msg);
  if (rc != DDS_RETCODE_OK)
    DDS_FATAL("dds_write: %s\n", dds_strretcode(-rc));

  /* Deleting the participant will delete all its children recursively as well. */
  rc = dds_delete (participant);
  if (rc != DDS_RETCODE_OK)
    DDS_FATAL("dds_delete: %s\n", dds_strretcode(-rc));

  return EXIT_SUCCESS;
}
