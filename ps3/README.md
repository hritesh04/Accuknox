**1. Explaining how the highlighted constructs work ?**

    chan or channels in golang are used as a communnication mechanism between go routines that provides the capabilty for synchronization between the go routines.

    Channel is like a queue of specific type and of specific length, the channels with no length is called unbuffered channel where the sender goroutine blocks the execution if there is no receiver providing synchronization, similarly the receiver also blocks its execution until there is no value in the channel

    The channel with fixed lenght is called buffered channel where the sender can keep on sending and will not block untill the channel is full.

**2. Giving use-cases of what these constructs could be used for.**

    Channel can be used to provide synchronization, act as a communication mechanism between goroutine and can provide asynchronous communication when used using buffered channel.

    This code snippet can also be used to create a producer/consumer model after some modification. Code in ps3.go file.

**3. What is the significance of the for loop with 4 iterations ?**

    The loop with 4 iterations creates 4 goroutine in which each goroutine loop over the cnp channel. All of these goroutines would be in block state as there is no value in the channel but as soon as a function put in the channel one of the gorutine pick it up from the channel and tries to execute it but before it can be executed the main control flow reaches the print "Hello" and exits the program killing all the other goroutines.

**4. What is the significance of make(chan func(), 10) ?**

    Using the make function a channel of type func() with length 10 i.e a buffered channel is initialized that acts as a communication medium between the 4 goroutines created in the following for loop and the main process.

**5. Why is “HERE1” not getting printed ?**

    "HERE1" is not getting printed because as soon as the function is put in the channel before the goroutines can pick it up and execute it the main control flow reaches the print "Hello" after which the main process exits killing all the goroutine in the process.