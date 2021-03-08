#include "dds/dds.h"
#include "HelloWorldData.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* An array of one message (aka sample in dds terms) will be used. */
#define MAX_SAMPLES 1

int main (int argc, char ** argv)
{
  dds_entity_t participant;
  dds_entity_t topic;
  dds_entity_t reader;
  HelloWorldData_Msg *msg;
  void *samples[MAX_SAMPLES];
  dds_sample_info_t infos[MAX_SAMPLES];
  dds_return_t rc;
  dds_qos_t *qos;
  (void)argc;
  (void)argv;

  dds_qos_t *qos_sec;
  qos_sec=dds_create_qos ();
  dds_qset_prop(qos_sec, "dds.sec.auth.library.path", "dds_security_auth");
  dds_qset_prop(qos_sec, "dds.sec.auth.library.init", "init_authentication");
  dds_qset_prop(qos_sec, "dds.sec.auth.library.finalize", "finalize_authentication");
  dds_qset_prop(qos_sec, "dds.sec.auth.identity_ca", "file://certs/maincacert.pem");
  dds_qset_prop(qos_sec, "dds.sec.auth.private_key", "file://certs/mainsubkey.pem");
  dds_qset_prop(qos_sec, "dds.sec.auth.identity_certificate", "file://certs/mainsubcert.pem");

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
  printf("\nqos setted\n");
  dds_delete_qos(qos_sec);
  if (participant < 0)
    DDS_FATAL("dds_create_participant: %s\n", dds_strretcode(-participant));

  /* Create a Topic. */
  topic = dds_create_topic (
    participant, &HelloWorldData_Msg_desc, "HelloWorldData_Msg", NULL, NULL);
  if (topic < 0)
    DDS_FATAL("dds_create_topic: %s\n", dds_strretcode(-topic));

  /* Create a reliable Reader. */
  qos = dds_create_qos ();
  dds_qset_reliability (qos, DDS_RELIABILITY_RELIABLE, DDS_SECS (10));
  reader = dds_create_reader (participant, topic, qos, NULL);
  if (reader < 0)
    DDS_FATAL("dds_create_reader: %s\n", dds_strretcode(-reader));
  dds_delete_qos(qos);

  printf ("\n=== [Subscriber] Waiting for a sample ...\n");
  fflush (stdout);

  /* Initialize sample buffer, by pointing the void pointer within
   * the buffer array to a valid sample memory location. */
  samples[0] = HelloWorldData_Msg__alloc ();

  /* Poll until data has been read. */
  while (true)
  {
    /* Do the actual read.
     * The return value contains the number of read samples. */
    rc = dds_read (reader, samples, infos, MAX_SAMPLES, MAX_SAMPLES);
    if (rc < 0)
      DDS_FATAL("dds_read: %s\n", dds_strretcode(-rc));

    /* Check if we read some data and it is valid. */
    if ((rc > 0) && (infos[0].valid_data))
    {
      /* Print Message. */
      msg = (HelloWorldData_Msg*) samples[0];
      printf ("=== [Subscriber] Received : ");
      printf ("Message (%"PRId32", %s)\n", msg->userID, msg->message);
      fflush (stdout);
      break;
    }
    else
    {
      /* Polling sleep. */
      dds_sleepfor (DDS_MSECS (20));
    }
  }

  /* Free the data location. */
  HelloWorldData_Msg_free (samples[0], DDS_FREE_ALL);

  /* Deleting the participant will delete all its children recursively as well. */
  rc = dds_delete (participant);
  if (rc != DDS_RETCODE_OK)
    DDS_FATAL("dds_delete: %s\n", dds_strretcode(-rc));

  return EXIT_SUCCESS;
}
