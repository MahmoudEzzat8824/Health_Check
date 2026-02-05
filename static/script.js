document.addEventListener('DOMContentLoaded', function() {
    const uploadForm = document.getElementById('uploadForm');
    const fileInput = document.getElementById('fileInput');
    const fileName = document.getElementById('fileName');
    const submitBtn = document.getElementById('submitBtn');
    const loading = document.getElementById('loading');
    const resultCard = document.getElementById('resultCard');
    const resultInfo = document.getElementById('resultInfo');
    const resultOutput = document.getElementById('resultOutput');
    const downloadBtn = document.getElementById('downloadBtn');
    const newCheckBtn = document.getElementById('newCheckBtn');
    
    let currentJobId = null;

    // File input change handler
    fileInput.addEventListener('change', function(e) {
        if (e.target.files.length > 0) {
            fileName.textContent = e.target.files[0].name;
        } else {
            fileName.textContent = 'Choose file...';
        }
    });

    // Form submit handler
    uploadForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const formData = new FormData(uploadForm);
        
        // Validate inputs
        const username = document.getElementById('username').value.trim();
        const file = fileInput.files[0];
        
        if (!username) {
            showAlert('Please enter an SSH username', 'error');
            return;
        }
        
        if (!file) {
            showAlert('Please select a server list file', 'error');
            return;
        }
        
        if (!file.name.endsWith('.txt')) {
            showAlert('Please upload a .txt file', 'error');
            return;
        }
        
        // Show loading state
        submitBtn.disabled = true;
        loading.style.display = 'block';
        resultCard.style.display = 'none';
        
        try {
            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Upload failed');
            }
            
            // Success - show results
            currentJobId = data.job_id;
            displayResults(data);
            
        } catch (error) {
            showAlert(error.message, 'error');
            console.error('Upload error:', error);
        } finally {
            loading.style.display = 'none';
            submitBtn.disabled = false;
        }
    });

    // Display results
    function displayResults(data) {
        resultCard.style.display = 'block';
        
        // Show info
        const statusClass = data.exit_code === 0 ? '' : 'error';
        resultInfo.className = `result-info ${statusClass}`;
        resultInfo.innerHTML = `
            <strong>${data.exit_code === 0 ? '✅ Success' : '⚠️ Completed with warnings'}</strong><br>
            <small>Job ID: ${data.job_id}</small><br>
            <small>${data.message}</small>
        `;
        
        // Show output
        resultOutput.textContent = data.output;
        
        // Scroll to results
        resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // Download button handler
    downloadBtn.addEventListener('click', function() {
        if (currentJobId) {
            window.location.href = `/api/download/${currentJobId}`;
        }
    });

    // New check button handler
    newCheckBtn.addEventListener('click', function() {
        uploadForm.reset();
        fileName.textContent = 'Choose file...';
        resultCard.style.display = 'none';
        currentJobId = null;
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });

    // Show alert helper
    function showAlert(message, type = 'error') {
        const existingAlert = document.querySelector('.alert');
        if (existingAlert) {
            existingAlert.remove();
        }
        
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        alert.textContent = message;
        
        uploadForm.parentElement.insertBefore(alert, uploadForm);
        
        setTimeout(() => {
            alert.remove();
        }, 5000);
    }

    // Drag and drop support
    const fileLabel = document.querySelector('.file-label');
    
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        fileLabel.addEventListener(eventName, preventDefaults, false);
    });
    
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    ['dragenter', 'dragover'].forEach(eventName => {
        fileLabel.addEventListener(eventName, highlight, false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        fileLabel.addEventListener(eventName, unhighlight, false);
    });
    
    function highlight(e) {
        fileLabel.style.borderColor = 'var(--primary-color)';
        fileLabel.style.background = '#eff6ff';
    }
    
    function unhighlight(e) {
        fileLabel.style.borderColor = 'var(--border-color)';
        fileLabel.style.background = 'var(--background)';
    }
    
    fileLabel.addEventListener('drop', handleDrop, false);
    
    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        
        if (files.length > 0) {
            fileInput.files = files;
            fileName.textContent = files[0].name;
        }
    }
});
