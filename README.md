# Huawei_E5186_API
Python3 Scripts to interact with a Huawei E5186

Written after too longtrying to find the correct way to get to Authenticate with the E5186, as a recent firmware update changed the authentication method. Works as of latest firmware in April 2018.

I would list the huge number of peoples 'other' code (C, Java, PHP, Python2 et al) that I had to look at to work this out.  The key was finding the Hash libraries that did work correctly,  knowing the strange way that the authentication worked.  Each interaction once logged in changes the token - so the code now reflects this better behavior


