### Yaml
- project use yaml-cpp library

- $extends - path to previous "layer", rewritten with actual file
- $validator - path to validator (json schema, but input is same in yaml format, default set default value)
- $DELETE - for deleting previous data (leave default)

- you have to replace all list, if you want 
#TODO is it true of internatal process solve it different?

### Process:

1 - in folder "B" what is test config 

2 - check \$extends (\$extends: <./path_to_A> for example)

3 - than "A" is validated, return yaml, wht is pasted to "B" node

4 - $validator are applied to yaml, result is validated yaml

(2-4 are recursion)

5 - final result is validated by test validator

There are some limits for circles etc. (important only for debugging)
For manual validation check [tester_test.md](tester_test.md) for manual test  manual_config_validation