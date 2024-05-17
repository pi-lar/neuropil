#include <sodium.h>
#include <sys/resource.h>
#include <time.h>

#include "util/np_bloom.h"

clock_t begin_t, finish_t;

double mean_time                 = 0;
double mean_time_create          = 0;
double mean_time_populate        = 0;
double mean_time_check100        = 0;
double mean_time_check0          = 0;
double mean_time_check50         = 0;
double mean_time_delete          = 0;
double mean_time_intersection    = 0;
double mean_time_union           = 0;
double start_size                = 0;
double end_size                  = 0;
double mean_size_create          = 0;
double mean_size_r2              = 0;
double mean_size_populate        = 0;
double mean_size_check100        = 0;
double mean_size_check50         = 0;
double mean_size_check0          = 0;
double mean_size_delete          = 0;
double mean_size_union           = 0;
double mean_size_intersect       = 0;
double mean_size                 = 0;
int    check_100                 = 0;
int    check_50                  = 0;
int    check_0                   = 0;
int    intersect_random_check    = 0;
int    intersect_50_check        = 0;
double mean_time_intersection_50 = 0;

uint16_t bloom_size = 65472;

int bloom_speed_test(int number_of_elements, int number_of_elements_to_check) {
  if (sodium_init() == -1) {
    return 1;
  }
  double        task_time  = 0;
  double        total_time = 0;
  struct rusage myusage;
  FILE         *fpt;
  fpt = fopen("Enhanced Bloom-Filter Daten (1024)(uint128 list).csv", "a+");
  fprintf(fpt, "%s, %s", "Step", "Time\n");

  // creation of bloom_1 and time measuring
  getrusage(RUSAGE_SELF, &myusage);
  start_size = myusage.ru_maxrss;
  begin_t    = clock();
  np_bloom_t *bloom_1;
  bloom_1  = _np_enhanced_bloom_create(bloom_size);
  finish_t = clock();
  getrusage(RUSAGE_SELF, &myusage);
  end_size         = myusage.ru_maxrss;
  mean_size_create = mean_size_create + end_size - start_size;
  task_time        = (double)(finish_t - begin_t) / CLOCKS_PER_SEC;
  mean_time_create = mean_time_create + task_time;
  total_time       = total_time + task_time;
  printf(
      "Die Dauer betrug %f Sekunden für das erstellen des Bloomfilter "
      "bloom_1.\n",
      task_time);
  fprintf(fpt, "Create Bloomfilter, %f\n", task_time);

  np_dhkey_t *data_array;
  data_array = (np_dhkey_t *)malloc(number_of_elements * sizeof(np_dhkey_t));

  for (int i = 0; i < number_of_elements; i++) {
    np_dhkey_t x  = {0};
    x.t[0]        = randombytes_uniform(3705032704);
    x.t[1]        = randombytes_uniform(3705032704);
    x.t[2]        = randombytes_uniform(3705032704);
    x.t[3]        = randombytes_uniform(3705032704);
    x.t[4]        = randombytes_uniform(3705032704);
    x.t[5]        = randombytes_uniform(3705032704);
    x.t[6]        = randombytes_uniform(3705032704);
    x.t[7]        = randombytes_uniform(3705032704);
    data_array[i] = x;
  }

  // time needed to fill bloom_1
  getrusage(RUSAGE_SELF, &myusage);
  start_size = myusage.ru_maxrss;
  begin_t    = clock();
  for (int i = 0; i < number_of_elements; i++) {
    _np_enhanced_bloom_add(bloom_1, data_array[i]);
  }
  finish_t = clock();
  getrusage(RUSAGE_SELF, &myusage);
  end_size           = myusage.ru_maxrss;
  mean_size_populate = mean_size_populate + end_size - start_size;
  task_time          = (double)(finish_t - begin_t) / CLOCKS_PER_SEC;
  mean_time_populate = mean_time_populate + task_time;
  total_time         = total_time + task_time;
  printf(
      "Die Dauer betrug %f Sekunden für das befüllen des Bloomfilter "
      "bloom_1.\n",
      task_time);
  fprintf(fpt, "Populate Bloomfilter, %f\n", task_time);

  np_dhkey_t *data_array_check;
  data_array_check =
      (np_dhkey_t *)malloc(number_of_elements * sizeof(np_dhkey_t));

  for (int i = 0; i < number_of_elements; i++) {
    np_dhkey_t x        = {0};
    x.t[0]              = randombytes_uniform(3705032704);
    x.t[1]              = randombytes_uniform(3705032704);
    x.t[2]              = randombytes_uniform(3705032704);
    x.t[3]              = randombytes_uniform(3705032704);
    x.t[4]              = randombytes_uniform(3705032704);
    x.t[5]              = randombytes_uniform(3705032704);
    x.t[6]              = randombytes_uniform(3705032704);
    x.t[7]              = randombytes_uniform(3705032704);
    data_array_check[i] = x;
  }
  printf("bloom_2 population\n");

  // bloom_2 creation and populating with data_array (identicalt to bloom_1)
  np_bloom_t *bloom_2;
  bloom_2 = _np_enhanced_bloom_create(bloom_size);
  for (int i = 0; i < number_of_elements; i++) {
    _np_enhanced_bloom_add(bloom_2, data_array[i]);
  }
  printf("bloom_3 population\n");

  // bloom_3 creation and populating with data_array (identicalt to bloom_1)
  np_bloom_t *bloom_3;
  bloom_3 = _np_enhanced_bloom_create(bloom_size);
  for (int i = 0; i < number_of_elements; i++) {
    _np_enhanced_bloom_add(bloom_3, data_array[i]);
  }

  // bloom_4 creation and populating with data_array_check
  printf("bloom_4 population starts\n");
  np_bloom_t *bloom_4;
  bloom_4 = _np_enhanced_bloom_create(bloom_size);
  for (int i = 0; i < number_of_elements; i++) {
    _np_enhanced_bloom_add(bloom_4, data_array_check[i]);
  }

  // bloom_5 creation and populating with data_array (identicalt to bloom_1)
  np_bloom_t *bloom_5;
  bloom_5 = _np_enhanced_bloom_create(bloom_size);
  for (int i = 0; i < number_of_elements; i++) {
    _np_enhanced_bloom_add(bloom_5, data_array[i]);
  }

  // bloom_6 creation and populating with data_array_check
  printf("bloom_6 population starts\n");
  np_bloom_t *bloom_6;
  bloom_6 = _np_enhanced_bloom_create(bloom_size);
  for (int i = 0; i < number_of_elements; i += 2) {
    _np_enhanced_bloom_add(bloom_6, data_array_check[i]);
  }
  for (int i = 0; i < number_of_elements; i += 2) {
    _np_enhanced_bloom_add(bloom_6, data_array[i]);
  }

  printf("bloom_4 populated\n");

  // Intersection of bloom_2 with bloom_4 for time measurement
  getrusage(RUSAGE_SELF, &myusage);
  start_size = myusage.ru_maxrss;
  printf("time1\n");
  begin_t = clock();
  printf("time2\n");
  intersect_random_check += _np_enhanced_bloom_intersect(bloom_2, bloom_4);
  printf("time3\n");
  finish_t = clock();
  getrusage(RUSAGE_SELF, &myusage);
  end_size               = myusage.ru_maxrss;
  mean_size_intersect    = mean_size_intersect + end_size - start_size;
  task_time              = (double)(finish_t - begin_t) / CLOCKS_PER_SEC;
  mean_time_intersection = mean_time_intersection + task_time;
  total_time             = total_time + task_time;
  printf(
      "Die Dauer betrug %f Sekunden für die Intersection von bloom_2 und "
      "bloom_4\n",
      task_time);
  fprintf(fpt, "Intersection of Bloomfilter, %f\n", task_time);

  // Intersection of bloom_5 with bloom_6 for time measurement
  getrusage(RUSAGE_SELF, &myusage);
  start_size = myusage.ru_maxrss;
  printf("time1\n");
  begin_t = clock();
  printf("time2\n");
  intersect_50_check += _np_enhanced_bloom_intersect(bloom_5, bloom_6);
  printf("time3\n");
  finish_t = clock();
  getrusage(RUSAGE_SELF, &myusage);
  end_size                  = myusage.ru_maxrss;
  mean_size_intersect       = mean_size_intersect + end_size - start_size;
  task_time                 = (double)(finish_t - begin_t) / CLOCKS_PER_SEC;
  mean_time_intersection_50 = mean_time_intersection_50 + task_time;
  total_time                = total_time + task_time;
  printf(
      "Die Dauer betrug %f Sekunden für die Intersection von bloom_5 und "
      "bloom_6\n",
      task_time);
  fprintf(fpt, "Intersection of Bloomfilter (50%% matching), %f\n", task_time);

  // Union of bloom_3 with bloom_4 for time measurement
  getrusage(RUSAGE_SELF, &myusage);
  start_size = myusage.ru_maxrss;
  begin_t    = clock();
  _np_enhanced_bloom_union(bloom_3, bloom_4);
  finish_t = clock();
  getrusage(RUSAGE_SELF, &myusage);
  end_size        = myusage.ru_maxrss;
  mean_size_union = mean_size_union + end_size - start_size;
  task_time       = (double)(finish_t - begin_t) / CLOCKS_PER_SEC;
  mean_time_union = mean_time_union + task_time;
  total_time      = total_time + task_time;
  printf("Die Dauer betrug %f Sekunden für die Union von bloom_3 und bloom_4\n",
         task_time);
  fprintf(fpt, "Union of Bloomfilter, %f\n", task_time);

  // time to check bloom_1 with 100% matching data set
  getrusage(RUSAGE_SELF, &myusage);
  start_size = myusage.ru_maxrss;
  begin_t    = clock();
  for (int i = 0; i < number_of_elements_to_check; i++) {
    check_100 = check_100 + _np_enhanced_bloom_check(bloom_1, data_array[i]);
  }
  finish_t = clock();
  getrusage(RUSAGE_SELF, &myusage);
  end_size           = myusage.ru_maxrss;
  mean_size_check100 = mean_size_check100 + end_size - start_size;
  task_time          = (double)(finish_t - begin_t) / CLOCKS_PER_SEC;
  mean_time_check100 = mean_time_check100 + task_time;
  total_time         = total_time + task_time;
  printf(
      "Die Dauer betrug %f Sekunden für das checken des Bloomfilters "
      "bloom_1.\n",
      task_time);
  fprintf(fpt, "100%% check Bloomfilter, %f\n", task_time);

  // time to check bloom_1 with 50% matching data set
  getrusage(RUSAGE_SELF, &myusage);
  start_size = myusage.ru_maxrss;
  begin_t    = clock();
  // two loops, one with the data array used to populate the bloomfilter and one
  // random one to get the same number of checked datapoints but with only 50%
  // matching
  for (int i = 0; i < (number_of_elements_to_check / 2); i++) {
    check_50 =
        check_50 + _np_enhanced_bloom_check(bloom_1, data_array_check[i]);
  }
  for (int i = 0; i < (number_of_elements_to_check / 2); i++) {
    check_50 = check_50 + _np_enhanced_bloom_check(bloom_1, data_array[i]);
  }
  finish_t = clock();
  getrusage(RUSAGE_SELF, &myusage);
  end_size          = myusage.ru_maxrss;
  mean_size_check50 = mean_size_check50 + end_size - start_size;
  task_time         = (double)(finish_t - begin_t) / CLOCKS_PER_SEC;
  mean_time_check50 = mean_time_check50 + task_time;
  total_time        = total_time + task_time;
  printf(
      "Die Dauer betrug %f Sekunden für das checken des Bloomfilters "
      "bloom_1.\n",
      task_time);
  fprintf(fpt, "50%% check Bloomfilter, %f\n", task_time);

  // time to check bloom_1 with 0% matching data set
  getrusage(RUSAGE_SELF, &myusage);
  start_size = myusage.ru_maxrss;
  begin_t    = clock();
  for (int i = 0; i < number_of_elements_to_check; i++) {
    check_0 = check_0 + _np_enhanced_bloom_check(bloom_1, data_array_check[i]);
  }
  finish_t = clock();
  getrusage(RUSAGE_SELF, &myusage);
  end_size         = myusage.ru_maxrss;
  mean_size_check0 = mean_size_check0 + end_size - start_size;
  task_time        = (double)(finish_t - begin_t) / CLOCKS_PER_SEC;
  mean_time_check0 = mean_time_check0 + task_time;
  total_time       = total_time + task_time;
  printf(
      "Die Dauer betrug %f Sekunden für das checken des Bloomfilters "
      "bloom_1.\n",
      task_time);
  fprintf(fpt, "0%% check Bloomfilter, %f\n", task_time);

  free(data_array);
  free(data_array_check);

  // deletion of bloom_1
  getrusage(RUSAGE_SELF, &myusage);
  start_size = myusage.ru_maxrss;
  begin_t    = clock();
  _np_enhanced_bloom_clear(bloom_1);
  _np_bloom_free(bloom_1);
  finish_t = clock();
  getrusage(RUSAGE_SELF, &myusage);
  end_size         = myusage.ru_maxrss;
  mean_size_delete = mean_size_delete + end_size - start_size;
  task_time        = (double)(finish_t - begin_t) / CLOCKS_PER_SEC;
  mean_time_delete = mean_time_delete + task_time;
  total_time       = total_time + task_time;
  printf(
      "Die Dauer betrug %f Sekunden für das Löschen des Bloomfilters "
      "bloom_1.\n",
      task_time);
  fprintf(fpt, "Deletion of Bloomfilter, %f\n", task_time);
  _np_enhanced_bloom_clear(bloom_2);
  _np_enhanced_bloom_clear(bloom_3);
  _np_enhanced_bloom_clear(bloom_4);
  _np_bloom_free(bloom_2);
  _np_bloom_free(bloom_3);
  _np_bloom_free(bloom_4);

  printf("Die Gesamtdauer beträgt %f Sekunden.\n", total_time);
  mean_time = mean_time + total_time;
  fprintf(fpt, "Total time for this cycle, %f\n", total_time);
  fclose(fpt);
  return 0;
}

int main() {
  int number_of_elements         = 0;
  int number_of_elements_checked = 0;
  int runs                       = 0;

  FILE *fpt;
  fpt = fopen("Enhanced Bloom-Filter Daten (1024)(uint128 list).csv", "w+");
  fclose(fpt);

  // Determination of number of elements in the filters and the number of
  // incoming requests
  printf("Wie viele Elemente sollen in den Bloomfilter eingetragen werden?\n");
  scanf("%d", &number_of_elements);
  printf("Wie viele Elemente sollen im Bloomfilter gesucht werden?\n");
  scanf("%d", &number_of_elements_checked);
  printf("\nAnzahl der Elemente beträgt %d\n", number_of_elements);
  printf(
      "Wie viele Durchläufe sollen mit bloom_speed_test durchgeführt "
      "werden?\n");
  scanf("%d", &runs);

  // for loop to build, populate and delete bloomfilters
  for (int i = 1; i <= runs; i++) {
    printf("\nFür Zyklus %d\n", i);
    bloom_speed_test(number_of_elements, number_of_elements_checked);
  }

  fpt = fopen("Enhanced Bloom-Filter Daten (1024)(uint128 list).csv", "a+");
  printf(
      "%f Sekunden ist die durchschnittliche Dauer für Erstellung bei %d "
      "Läufen.\n",
      (mean_time_create / runs),
      runs);
  fprintf(fpt, "Mean Time Create Bloomfilter, %f\n", mean_time_create);
  printf(
      "%f Sekunden ist die durchschnittliche Dauer für das Befüllen bei %d "
      "Läufen.\n",
      (mean_time_populate / runs),
      runs);
  fprintf(fpt, "Mean Time populate Bloomfilter, %f\n", mean_time_populate);
  printf(
      "%f Sekunden ist die durchschnittliche Dauer für das 100 Prozent "
      "Suchen "
      "bei %d "
      "Läufen.\n",
      (mean_time_check100 / runs),
      runs);
  fprintf(fpt, "Mean Time Check 100%% Bloomfilter, %f\n", mean_time_check100);
  printf(
      "%f Sekunden ist die durchschnittliche Dauer für das 50 Prozent Suchen "
      "bei %d "
      "Läufen.\n",
      (mean_time_check50 / runs),
      runs);
  fprintf(fpt, "Mean Time Check 50%% Bloomfilter, %f\n", mean_time_check50);
  printf(
      "%f Sekunden ist die durchschnittliche Dauer für das 0 Prozent Suchen "
      "bei %d "
      "Läufen.\n",
      (mean_time_check0 / runs),
      runs);
  fprintf(fpt, "Mean Time Check 0%% Bloomfilter, %f\n", mean_time_check0);
  printf(
      "%f Sekunden ist die durchschnittliche Dauer für das Löschen bei %d "
      "Läufen.\n",
      (mean_time_delete / runs),
      runs);
  fprintf(fpt, "Mean Time delete Bloomfilter, %f\n", mean_time_check100);
  printf(
      "%f Sekunden ist die durchschnittliche Dauer für die Union bei %d "
      "Läufen.\n",
      (mean_time_union / runs),
      runs);
  fprintf(fpt, "Mean Time Union Bloomfilter, %f\n", mean_time_union);
  printf(
      "%f Sekunden ist die durchschnittliche Dauer für die Intersection bei %d "
      "Läufen.\n",
      (mean_time_intersection / runs),
      runs);
  fprintf(fpt,
          "Mean Time Intersection Bloomfilter, %f\n",
          mean_time_intersection);
  printf(
      "%f Sekunden ist die durchschnittliche Dauer für die Intersection_50%% "
      "bei %d Läufen.\n",
      (mean_time_intersection_50 / runs),
      runs);
  fprintf(fpt,
          "Mean Time Intersection Bloomfilter, %f\n",
          mean_time_intersection_50);
  printf(
      "%f Sekunden ist die durchschnittliche Dauer für alle Schritte "
      "zusammen "
      "bei %d Läufen.\n",
      (mean_time / runs),
      runs);
  fprintf(fpt, "Mean Time for all steps Bloomfilter, %f\n", mean_time);
  fclose(fpt);
  printf("Check 0%%: %d\n", check_0);
  printf("Check 50%%: %d\n", check_50);
  printf("Check 100%%: %d\n", check_100);
  printf("Intersect Random: %d\n", intersect_random_check);
  printf("Intersect 50%%: %d\n", intersect_50_check);
  // printf(
  //     "%f Byte ist die durchschnittliche Größe für das Erstellen "
  //     "bei %d Läufen.\n",
  //     ((double)(mean_size_create)) / runs,
  //     runs);
  // printf(
  //     "%f Byte ist die durchschnittliche Größe für das Befüllen per add many"
  //     "bei %d Läufen.\n",
  //     ((double)(mean_size_r2)) / runs,
  //     runs);
  // printf(
  //     "%f Byte ist die durchschnittliche Größe für das Befüllen per add bulk
  //     " "bei %d Läufen.\n",
  //     ((double)(mean_size_populate)) / runs,
  //     runs);
  // printf(
  //     "%f Byte ist die durchschnittliche Größe für das prüfen mit 100%% "
  //     "Übereinstimmung "
  //     "bei %d Läufen.\n",
  //     ((double)(mean_size_check100)) / runs,
  //     runs);
  // printf(
  //     "%f Byte ist die durchschnittliche Größe für das prüfen mit 50%% "
  //     "Übereinstimmung"
  //     "bei %d Läufen.\n",
  //     ((double)(mean_size_check50)) / runs,
  //     runs);
  // printf(
  //     "%f Byte ist die durchschnittliche Größe für das prüfen mit 0%% "
  //     "Übereinstimmung"
  //     "bei %d Läufen.\n",
  //     ((double)(mean_size_check0)) / runs,
  //     runs);
  // printf(
  //     "%f Byte ist die durchschnittliche Größe für die Union"
  //     "bei %d Läufen.\n",
  //     ((double)(mean_size_union)) / runs,
  //     runs);
  // printf(
  //     "%f Byte ist die durchschnittliche Größe für die Intersection"
  //     "bei %d Läufen.\n",
  //     ((double)(mean_size_intersect)) / runs,
  //     runs);
  // printf(
  //     "%f Byte ist die durchschnittliche Größe für das Löschen"
  //     "bei %d Läufen.\n",
  //     ((double)(mean_size_delete)) / runs,
  //     runs);
  // mean_size = mean_size_create + mean_size_populate + mean_size_check100 +
  //             mean_size_check50 + mean_size_check0 + mean_size_union +
  //             mean_size_intersect + mean_size_delete;
  // printf(
  //     "%f Byte ist die durchschnittliche Gesamtgröße"
  //     "bei %d Läufen.\n",
  //     ((double)(mean_size)) / runs,
  //     runs);

  return 0;
}
