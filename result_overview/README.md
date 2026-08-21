Dont include data itself
Raw data are stored in <root>/data and will be available later (in separated git, outside github)

Why?
reports are still repeatable and there sometimes need to be, because, its still user friendly debug tool.
I need reports fast and easy.
But I need something for upside view too, something from database perspective - and html looks ok for this.
I need something with extended table visual options.

--- DISCLAIMER 
I try use as little JavaScript as possible, because JavaScript is horrible language.
I don't use JavaScript to make page "looks better", I use is for readability.
I didn't found simple other way - sorry for that.

## For developers

### How add new attack page?
- add link to page to [main.cpp](src/main.cpp)
- add page to [attacks](src/attacks) by [attacks](../wpa3_test/src/attacks) structure
- add parsing in [visual](../wpa3_test/src/visual) with Entry  [visual](../wpa3_test/include/visual)