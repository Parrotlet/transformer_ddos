import concurrent.futures


def say_hello_to(x,y):
    x=x*2
    y=y*2
    return x,y


x1 = [1,2,3]
y1 = [4,5,6]

with concurrent.futures.ProcessPoolExecutor(max_workers=16) as executor:
    results = executor.map(say_hello_to, x1,y1)

# for r in results:
#     print(r)