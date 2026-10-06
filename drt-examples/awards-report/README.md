# Awards Report

Lists award records with eleven fields, from Staff Number to Exam Board
Date, filtered by exam board date range, award, staff number and membership
number, sorted on any field and paged (100 rows by default, 500 at most).
Analysts see only the rows their employer scope allows; admins see every row.

The columns match the awards export's header exactly:

```
Staff Number,Membership Number,Title,First Name,Surname,Date of Birth,Employer,Employer Group,Award,Award Grade,Exam Board Date
```

`fixtures/awards-synthetic.csv` has that header and 25 synthetic rows, with
made-up employers, awards and people:

- 12 in employer group Group A, 4 of them with employer Bank A Network;
- 7 in Group B and 4 in Group C;
- 2 with no employer group, which no employer group scope matches.

Its exam board dates include 31/12/2025, 01/01/2026, 30/09/2026 and
01/10/2026, around a 2026 date range, and its staff numbers keep leading
zeroes (`000123`, `0099`).
