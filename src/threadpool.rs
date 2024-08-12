use std::sync;

type Job = Box<dyn FnOnce() + Send + 'static>;

pub struct Worker {
    id: usize,
    thread: Option<std::thread::JoinHandle<()>>
}

impl Worker {
    pub fn new(id: usize, receiver: sync::Arc<sync::Mutex<sync::mpsc::Receiver<Job>>>) -> Worker {
        let thread = std::thread::spawn(move || loop {
           let message = receiver.lock().unwrap().recv();

            match message {
                Ok(job) => {
                    job();
                },
                Err(_) => {
                    break;
                }
            }
        });

        Worker {
            id: id,
            thread: Some(thread)
        }
    }
}

pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: Option<sync::mpsc::Sender<Job>>
}

impl ThreadPool {
    pub fn new(size: usize) -> ThreadPool {
        let (sender, receiver) = sync::mpsc::channel();
        let receiver = sync::Arc::new(sync::Mutex::new(receiver));

        let mut  workers = Vec::<Worker>::with_capacity(size);
        for id in 0..size {
            workers.push(Worker::new(id, sync::Arc::clone(&receiver)));
        }

        ThreadPool {
            workers: workers,
            sender: Some(sender)
        }
    }

    pub fn exec<F>(&self, fnc: F) where F: FnOnce() + Send + 'static {
        let job = Box::new(fnc);
        self.sender.as_ref().unwrap().send(job).unwrap()
    }
}