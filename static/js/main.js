document.addEventListener('DOMContentLoaded', () => {
    // Initialize scroll animations with a lower threshold for better visibility
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -20px 0px'
    };

    const fadeElements = document.querySelectorAll('.fade-in');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, observerOptions);

    fadeElements.forEach(element => {
        observer.observe(element);
    });

    // Add fade-in class to posts and cards with shorter delay
    document.querySelectorAll('.card, .post-card').forEach((element, index) => {
        element.classList.add('fade-in');
        element.style.transitionDelay = `${index * 0.05}s`;
    });

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            document.querySelector(this.getAttribute('href')).scrollIntoView({
                behavior: 'smooth'
            });
        });
    });

    // Initialize Bootstrap tooltips
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));

    // Add hover effect to navigation items
    const navItems = document.querySelectorAll('.nav-link');
    navItems.forEach(item => {
        item.addEventListener('mouseenter', () => {
            item.style.transform = 'translateY(-2px)';
        });
        item.addEventListener('mouseleave', () => {
            item.style.transform = 'translateY(0)';
        });
    });

    // Animate flash messages with improved timing
    const flashMessages = document.querySelectorAll('.alert');
    flashMessages.forEach(message => {
        message.style.animation = 'slideIn 0.5s ease-out';
        setTimeout(() => {
            message.classList.add('hiding');
            message.addEventListener('transitionend', () => {
                message.style.display = 'none';
            });
        }, 5000);
    });

    // Admin code field toggle with smooth transition
    const isAdminCheckbox = document.getElementById('is_admin');
    const adminCodeField = document.querySelector('.admin-code');

    if (isAdminCheckbox && adminCodeField) {
        adminCodeField.style.transition = 'all 0.3s ease-in-out';
        adminCodeField.style.maxHeight = '0';
        adminCodeField.style.opacity = '0';
        adminCodeField.style.overflow = 'hidden';

        isAdminCheckbox.addEventListener('change', function() {
            if (this.checked) {
                adminCodeField.style.display = 'block';
                setTimeout(() => {
                    adminCodeField.style.maxHeight = '100px';
                    adminCodeField.style.opacity = '1';
                }, 10);
            } else {
                adminCodeField.style.maxHeight = '0';
                adminCodeField.style.opacity = '0';
                setTimeout(() => {
                    adminCodeField.style.display = 'none';
                }, 300);
            }
        });
    }

    // Library-specific animations and functionality
    document.addEventListener('DOMContentLoaded', () => {
        // Initialize PDF.js for book previews
        pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
    
        // Book card hover effects
        const bookCards = document.querySelectorAll('.book-card');
        bookCards.forEach(card => {
            card.addEventListener('mouseenter', () => {
                card.style.transform = 'translateY(-10px) scale(1.02)';
                card.style.boxShadow = '0 10px 20px rgba(0, 0, 0, 0.3)';
            });
            card.addEventListener('mouseleave', () => {
                card.style.transform = 'translateY(0) scale(1)';
                card.style.boxShadow = '0 4px 6px rgba(0, 0, 0, 0.1)';
            });
        });
    
        // PDF Preview functionality
        const previewButtons = document.querySelectorAll('.preview-btn');
        const pdfPreviewModal = document.getElementById('pdfPreviewModal');
        const pdfViewer = document.getElementById('pdfViewer');
    
        previewButtons.forEach(button => {
            button.addEventListener('click', async () => {
                const pdfUrl = button.dataset.pdfUrl;
                try {
                    const loadingTask = pdfjsLib.getDocument(pdfUrl);
                    const pdf = await loadingTask.promise;
                    const page = await pdf.getPage(1);
                    const viewport = page.getViewport({ scale: 1.5 });
    
                    const canvas = document.createElement('canvas');
                    const context = canvas.getContext('2d');
                    canvas.height = viewport.height;
                    canvas.width = viewport.width;
    
                    pdfViewer.innerHTML = '';
                    pdfViewer.appendChild(canvas);
    
                    await page.render({
                        canvasContext: context,
                        viewport: viewport
                    }).promise;
    
                    const modal = new bootstrap.Modal(pdfPreviewModal);
                    modal.show();
                } catch (error) {
                    console.error('Error loading PDF:', error);
                    alert('Error loading PDF preview');
                }
            });
        });
    
        // Handle book upload form submission
        const addBookForm = document.getElementById('addBookForm');
        if (addBookForm) {
            addBookForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                const formData = new FormData(addBookForm);
    
                try {
                    const response = await fetch('/library/add_book', {
                        method: 'POST',
                        body: formData
                    });
    
                    if (response.ok) {
                        location.reload();
                    } else {
                        throw new Error('Failed to add book');
                    }
                } catch (error) {
                    console.error('Error adding book:', error);
                    alert('Error adding book');
                }
            });
        }
    });
    
    // Add library-specific CSS animations
    const libraryStyles = document.createElement('style');
    libraryStyles.textContent = `
        .library-container {
            padding: 2rem;
        }
    
        .library-title {
            text-align: center;
            margin-bottom: 3rem;
            color: var(--text-primary);
        }
    
        .book-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 2rem;
            padding: 1rem;
        }
    
        .book-card {
            background: var(--card-gradient);
            border-radius: 10px;
            overflow: hidden;
            transition: all 0.3s ease;
        }
    
        .book-cover {
            position: relative;
            padding-top: 150%;
            overflow: hidden;
        }
    
        .book-cover img {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            object-fit: cover;
            transition: transform 0.3s ease;
        }
    
        .book-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 0;
            transition: opacity 0.3s ease;
        }
    
        .book-card:hover .book-overlay {
            opacity: 1;
        }
    
        .book-info {
            padding: 1.5rem;
        }
    
        .book-info h3 {
            margin: 0;
            font-size: 1.2rem;
            color: var(--text-primary);
        }
    
        .book-info .author {
            color: var(--text-muted);
            margin: 0.5rem 0;
        }
    
        .book-info .description {
            font-size: 0.9rem;
            color: var(--text-secondary);
            margin: 0;
        }
    
        .pdf-container {
            max-height: 80vh;
            overflow-y: auto;
            display: flex;
            justify-content: center;
            background: #333;
            padding: 1rem;
        }
    
        .pdf-container canvas {
            max-width: 100%;
            height: auto;
        }
    
        .admin-controls {
            text-align: right;
            margin-bottom: 2rem;
        }
    `;
    document.head.appendChild(libraryStyles);
    
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateY(-100%); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
    
        .nav-link {
            transition: transform 0.3s ease;
        }
    
        .fade-in {
            opacity: 0;
            transform: translateY(20px);
            transition: opacity 0.6s ease-out, transform 0.6s ease-out;
        }
    
        .fade-in.visible {
            opacity: 1;
            transform: translateY(0);
        }
    
        .alert {
            transition: opacity 0.3s ease-out;
        }
    
        .alert.hiding {
            opacity: 0;
        }
    
        .card, .post-card {
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
    
        .card:hover, .post-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }
    `;
    document.head.appendChild(style);});
