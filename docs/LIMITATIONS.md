# Limitations and Caveats

## Pattern-Matching

### AWS Secret Keys

The AWS secret keys are 40 character strings in the `base64` alphabet. Right now
they are set to match last but the pattern for them could easily trigger false
positives if there is a lot of base64 alphabet strings being dumped into an LLM.

You may want to turn matches on those off if this is the case. However, it may
not be noticeable that it is even being matched except it probably would run
slow if there is a lot of base64 data.
