#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

/* A sample program that demonstrates the use of threads.  Please note that
   this program was tested on nimitz. */

/* This info struct is used for passing parameters from the main thread to
   worker threads */

  typedef struct {
		int searchfor;
                /* you can add all the other fields you may need */
              } info;

/* This database is created by the main thread and used to store numbers in
   sorted order for searching. */

  int database[10];


/* This worker thread takes in a struct info as input and performs a binary
   search.  It prints appropriate message and performs a normal exit */

void * worker ( void * arg)
{
  int low, high, mid;    /* used for the binary search */
  int found;

  info *myinfo;
  info lookinfo;

  myinfo = (info *) arg;
  lookinfo = *myinfo;

  printf ("I have entered the search for %d\n",lookinfo.searchfor);
  fflush(stdout);  /** you need to flush the stdout **/

  low = 0;
  high = 9;
  found = 0;

  while ((low < high) && (found == 0)){
	mid = (int)(low+high)/2;
        if (database[mid] == lookinfo.searchfor) 
           found = 1;
        else if (database[mid] > lookinfo.searchfor) 
		high = mid - 1;
	     else 
		low = mid + 1;
  }

  if (found) printf ("The number %d was found\n", lookinfo.searchfor);
  else printf ("The number %d was not found\n", lookinfo.searchfor);
  fflush(stdout);  /** you need to flush the stdout **/
  
  pthread_exit(NULL);
}

int main (void)
{
  pthread_t threads[3];   /* the three thread object's indentifiers */
  void *exit_value;
  int status;
  info i1, i2, i3;
  int i;

/* I am creating a dummy database - Note that it is sorted */

  for (i=0; i<10; i++) {
      database[i] = i*2;
  }
  

/* Create the first thread and ask it to look for a number 8 */
   
  i1.searchfor = 8;

  status = pthread_create (&threads[0], NULL, worker, &i1);

/* Create the second thread and ask it to look for a number 14 */

  i2.searchfor = 2;

  status = pthread_create (&threads[1], NULL, worker, &i2);

/* Create the third thread and ask it to look for a number 15 */

  i3.searchfor = 9;
  status = pthread_create (&threads[2], NULL, worker, &i3);

/* Wait for the three threads to complete -- Note that this is a blocking wait */

  status = pthread_join (threads[0], &exit_value);
  status = pthread_join (threads[1], &exit_value);
  status = pthread_join (threads[2], &exit_value);

  return 0;

} /* End of the main program */

