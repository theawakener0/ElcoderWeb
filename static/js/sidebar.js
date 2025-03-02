document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const selectors = {
        sidebar: '.sidebar',
        mainContent: '.main-content',
        sidebarToggle: '.sidebar-toggle',
        navbarToggle: '.navbar-sidebar-toggle',
        sidebarLinks: '.sidebar-link, .sidebar-nav a'
    };

    const elements = {
        sidebar: document.querySelector(selectors.sidebar),
        mainContent: document.querySelector(selectors.mainContent),
        sidebarToggle: document.querySelector(selectors.sidebarToggle),
        navbarToggle: document.querySelector(selectors.navbarToggle),
        sidebarLinks: document.querySelectorAll(selectors.sidebarLinks)
    };

    // Exit if essential elements are missing
    if (!elements.sidebar || !elements.mainContent) return;

    // State Management
    const mediaQuery = window.matchMedia('(max-width: 768px)');
    const storageKey = 'sidebarState';
    
    // Initialization
    initializeSidebarState();
    highlightActiveLinks();
    setupEventListeners();

    function initializeSidebarState() {
        const savedState = localStorage.getItem(storageKey);
        const isMobile = mediaQuery.matches;
        
        if (savedState === 'collapsed' && !isMobile) {
            toggleSidebar(true);
        }
        
        if (isMobile) {
            toggleSidebar(true);
        }
    }

    function toggleSidebar(isCollapsed) {
        // Toggle visibility classes
        elements.sidebar.classList.toggle('collapsed', isCollapsed);
        elements.mainContent.classList.toggle('expanded', isCollapsed);
        
        // Update display property before other changes
        elements.sidebar.style.display = isCollapsed ? 'none' : 'block';
        
        // Add a small delay to ensure display property is applied
        setTimeout(() => {
            // Toggle visibility classes
            elements.sidebar.classList.toggle('visible', !isCollapsed);
            
            // Save state for non-mobile
            if (!mediaQuery.matches) {
                localStorage.setItem(storageKey, isCollapsed ? 'collapsed' : 'expanded');
            }
        }, 10);
    }

    function handleToggleClick(e) {
        e.preventDefault();
        const isCollapsed = elements.sidebar.classList.contains('collapsed');
        toggleSidebar(!isCollapsed);
    }

    function handleClickOutside(event) {
        const {sidebar, sidebarToggle, navbarToggle} = elements;
        const clickedOutside = !sidebar.contains(event.target) && 
                            !sidebarToggle?.contains(event.target) && 
                            !navbarToggle?.contains(event.target);

        if (clickedOutside && mediaQuery.matches && !sidebar.classList.contains('collapsed')) {
            toggleSidebar(true);
        }
    }

    function highlightActiveLinks() {
        const currentPath = window.location.pathname;
        elements.sidebarLinks.forEach(link => {
            const linkPath = new URL(link.href).pathname;
            link.classList.toggle('active', linkPath === currentPath);
        });
    }

    function handleMediaChange(e) {
        toggleSidebar(e.matches);
        if (e.matches) {
            localStorage.removeItem(storageKey);
        }
    }

    function setupEventListeners() {
        // Toggle buttons with improved event handling
        [elements.sidebarToggle, elements.navbarToggle].forEach(toggle => {
            if (toggle) {
                toggle.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    const isCollapsed = elements.sidebar.classList.contains('collapsed');
                    toggleSidebar(!isCollapsed);
                });
                toggle.style.cursor = 'pointer';
            }
        });
    
        // Mobile behavior
        mediaQuery.addListener(handleMediaChange);
        document.addEventListener('click', handleClickOutside);
    
        // Initialize media query handler
        handleMediaChange(mediaQuery);
    }
});
