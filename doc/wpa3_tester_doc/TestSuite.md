## Test suites
- have tbe in format [test_suite_validator.schema.yaml](../../wpa3_test/attack_config/validator/test_suite_validator.schema.yaml)
- config_type: test_suite
- path/generatros/permutation

##### name
- test if found from root with by test name
##### generator
- var_{var_name} placeholders
- for further description check schema
- config generating to  {rss.run_folder}/test_config/<generator_name>
##### permutation
- generate all combinations
- if var have more values than used, values are rotated
- var_{var_name} placeholders
#### actor_filler 
- only for internal for now #TODO 
- actors are declared by test, but it tries all possible options for available connected actors 