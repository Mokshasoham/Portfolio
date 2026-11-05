/**
 * CreativePort — Portfolio Generator JS
 * Complete workflow for portfolio creation, preview, and management
 */

class PortfolioGenerator {
    constructor() {
        this.currentStep = 'upload';
        this.parsedData = null;
        this.portfolioData = null;
        this.selectedTemplate = null;
        this.isGenerating = false;

        this.init();
    }

    apiUrl(path) {
        return new URL(path, window.location.href).toString();
    }

    isSuccess(result) {
        return result && (result.success === true || result.status === 'success');
    }

    getError(result, fallback) {
        return (result && (result.error || result.message)) || fallback;
    }

    async init() {
        this.attachEventListeners();
        await this.loadTemplatesList();
    }

    attachEventListeners() {
        // Resume upload
        document.getElementById('resumeInput')?.addEventListener('change', (e) => this.handleResumeUpload(e));

        // Manual data input
        document.getElementById('portfolioForm')?.addEventListener('change', (e) => this.handleFormChange(e));

        // Template selection
        document.querySelectorAll('[data-select-template]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const trigger = e.currentTarget;
                this.selectTemplate(trigger.dataset.selectTemplate, trigger);
            });
        });

        // Template preview
        document.querySelectorAll('[data-preview-template]').forEach(btn => {
            btn.addEventListener('click', (e) => this.previewTemplate(e.target.dataset.previewTemplate));
        });

        // Preview in modal
        document.getElementById('previewModal')?.addEventListener('click', (e) => {
            if (e.target.id === 'previewModal') this.closePreview();
        });

        // Generate button
        document.getElementById('generateBtn')?.addEventListener('click', () => this.startGeneration());

        // Publish button
        document.getElementById('publishBtn')?.addEventListener('click', () => this.publishPortfolio());
    }

    // ─── FILE UPLOAD & PARSING ─────────────────────────────

    async handleResumeUpload(event) {
        const file = event.target.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('action', 'parse_resume');
        formData.append('resume', file);

        this.showLoading('Analyzing your resume...');

        try {
            const response = await fetch(this.apiUrl('api/portfolio_generator.php'), {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (this.isSuccess(result)) {
                this.parsedData = result.data.parsed;
                this.showStep('templates');
                this.showNotification('Resume parsed successfully! ✨', 'success');
                this.updateFormWithParsedData();
            } else {
                this.showNotification(this.getError(result, 'Failed to parse resume'), 'error');
            }
        } catch (err) {
            this.showNotification('Error uploading resume: ' + err.message, 'error');
        }

        this.hideLoading();
    }

    handleFormChange(event) {
        const { name, value } = event.target;
        
        if (!this.portfolioData) {
            this.portfolioData = { ...this.parsedData };
        }

        // Update nested objects
        if (name.includes('.')) {
            const [parent, child] = name.split('.');
            if (this.portfolioData[parent]) {
                this.portfolioData[parent][child] = value;
            }
        } else {
            this.portfolioData[name] = value;
        }
    }

    updateFormWithParsedData() {
        if (!this.parsedData) return;

        // Auto-fill form fields with parsed data
        const fields = ['name', 'job_title', 'email', 'phone', 'location'];
        fields.forEach(field => {
            const input = document.getElementById(field);
            if (input && this.parsedData[field]) {
                input.value = this.parsedData[field];
            }
        });

        // Update portfolio data
        this.portfolioData = { ...this.parsedData };
    }

    // ─── TEMPLATE MANAGEMENT ────────────────────────────

    async loadTemplatesList() {
        try {
            const formData = new FormData();
            formData.append('action', 'get_templates');

            const response = await fetch(this.apiUrl('api/portfolio_generator.php'), {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (this.isSuccess(result)) {
                this.templates = result.data.templates;
                this.renderTemplateCards();
            }
        } catch (err) {
            console.error('Failed to load templates:', err);
        }
    }

    renderTemplateCards() {
        const grid = document.getElementById('templateGrid');
        if (!grid) return;

        grid.innerHTML = this.templates.map(t => `
            <div class="template-card">
                <div class="template-preview" style="background: linear-gradient(135deg, ${t.color_scheme[0]}, ${t.color_scheme[1]});">
                    <img src="${t.preview_image}" alt="${t.name}" class="template-img">
                </div>
                <div class="template-info">
                    <h3>${t.name}</h3>
                    <p>${t.description}</p>
                    <div class="template-features">
                        ${t.features.map(f => `<span class="feature-tag">${f}</span>`).join('')}
                    </div>
                    <div class="template-actions">
                        <button class="btn btn-secondary" data-preview-template="${t.id}">
                            <i class="fas fa-eye"></i> Preview
                        </button>
                        <button class="btn btn-primary" data-select-template="${t.id}">
                            <i class="fas fa-check"></i> Choose
                        </button>
                    </div>
                </div>
            </div>
        `).join('');

        // Re-attach event listeners
        this.attachEventListeners();
    }

    selectTemplate(template_id, trigger = null) {
        this.selectedTemplate = template_id;
        
        // Visual feedback
        document.querySelectorAll('[data-select-template]').forEach(btn => {
            btn.closest('.template-card').classList.remove('selected');
        });
        trigger?.closest('.template-card')?.classList.add('selected');

        this.showNotification(`Template "${template_id}" selected!`, 'success');
        this.showStep('review');
    }

    async previewTemplate(template_id) {
        if (!this.portfolioData) {
            this.showNotification('Please fill in your details first', 'warning');
            return;
        }

        const formData = new FormData();
        formData.append('action', 'preview_template');
        formData.append('template_id', template_id);
        formData.append('user_data', JSON.stringify(this.portfolioData));

        this.showLoading('Generating preview...');

        try {
            const response = await fetch(this.apiUrl('api/portfolio_generator.php'), {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (this.isSuccess(result)) {
                this.showPreviewModal(result.data.html);
            } else {
                this.showNotification(this.getError(result, 'Preview generation failed'), 'error');
            }
        } catch (err) {
            this.showNotification('Error generating preview: ' + err.message, 'error');
        }

        this.hideLoading();
    }

    showPreviewModal(html) {
        const modal = document.getElementById('previewModal');
        if (!modal) return;

        const iframe = modal.querySelector('iframe');
        iframe.srcdoc = html;

        modal.style.display = 'flex';
    }

    closePreview() {
        const modal = document.getElementById('previewModal');
        if (modal) modal.style.display = 'none';
    }

    // ─── GENERATION WORKFLOW ───────────────────────────

    async startGeneration() {
        if (!this.selectedTemplate) {
            this.showNotification('Please select a template first', 'warning');
            return;
        }

        if (!this.portfolioData) {
            this.showNotification('Please provide your portfolio details', 'warning');
            return;
        }

        this.isGenerating = true;
        this.showGenerationSteps();

        const steps = [
            { name: 'Analyzing Resume', delay: 1000 },
            { name: 'Extracting Skills', delay: 1500 },
            { name: 'Generating Content', delay: 2000 },
            { name: 'Applying Template', delay: 1500 },
            { name: 'Finalizing Portfolio', delay: 1000 }
        ];

        for (const step of steps) {
            await this.updateGenerationStep(step.name);
            await this.delay(step.delay);
        }

        // Final generation
        await this.generatePortfolio();
    }

    showGenerationSteps() {
        const container = document.getElementById('generationContainer');
        if (!container) return;

        container.innerHTML = `
            <div class="generation-modal">
                <div class="generation-content">
                    <h2>🚀 Creating Your Portfolio</h2>
                    <div class="generation-steps">
                        <div class="step active">
                            <div class="step-dot"></div>
                            <div class="step-text">
                                <div class="step-name" id="stepName">Preparing...</div>
                                <div class="step-progress">
                                    <div class="progress-bar"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    async updateGenerationStep(name) {
        const stepName = document.getElementById('stepName');
        if (stepName) stepName.textContent = name;
    }

    async generatePortfolio() {
        const formData = new FormData();
        formData.append('action', 'generate_portfolio');
        formData.append('portfolio_data', JSON.stringify(this.portfolioData));
        formData.append('template_id', this.selectedTemplate);
        formData.append('is_public', document.getElementById('isPublic')?.checked || false);

        try {
            const response = await fetch(this.apiUrl('api/portfolio_generator.php'), {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (this.isSuccess(result)) {
                this.showSuccessModal(result.data);
            } else {
                this.showNotification(this.getError(result, 'Generation failed'), 'error');
            }
        } catch (err) {
            this.showNotification('Error: ' + err.message, 'error');
        }

        this.isGenerating = false;
    }

    showSuccessModal(data) {
        const container = document.getElementById('generationContainer');
        if (!container) return;

        container.innerHTML = `
            <div class="generation-modal">
                <div class="generation-content success">
                    <div class="success-icon">✨</div>
                    <h2>Portfolio Created Successfully!</h2>
                    <p>Your portfolio is now live and ready to share</p>
                    
                    <div class="success-links">
                        <a href="${data.url}" target="_blank" class="btn btn-primary">
                            <i class="fas fa-external-link-alt"></i> View Portfolio
                        </a>
                        <button onclick="generator.editPortfolio(${data.portfolio_id})" class="btn btn-secondary">
                            <i class="fas fa-edit"></i> Edit
                        </button>
                    </div>

                    <div class="portfolio-info">
                        <div class="info-item">
                            <label>Portfolio URL:</label>
                            <code class="copy-able" data-copy="${data.url}">${data.url}</code>
                        </div>
                        <div class="info-item">
                            <label>Portfolio ID:</label>
                            <code>${data.portfolio_id}</code>
                        </div>
                        ${data.is_public ? `
                            <div class="info-item success">
                                <i class="fas fa-globe"></i> Public Portfolio - Visible to everyone
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;
    }

    // ─── UI HELPERS ────────────────────────────────────

    showStep(step) {
        this.currentStep = step;
        document.querySelectorAll('[data-step]').forEach(el => {
            el.style.display = el.dataset.step === step ? 'block' : 'none';
        });
    }

    showNotification(message, type = 'info') {
        const container = document.getElementById('notificationContainer') || this.createNotificationContainer();
        
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${this.getIconForType(type)}"></i>
                <span>${message}</span>
            </div>
            <button class="notification-close">&times;</button>
        `;

        container.appendChild(notification);

        notification.querySelector('.notification-close').addEventListener('click', () => {
            notification.remove();
        });

        setTimeout(() => notification.remove(), 5000);
    }

    getIconForType(type) {
        return { success: 'check-circle', error: 'times-circle', warning: 'exclamation-circle', info: 'info-circle' }[type] || 'info-circle';
    }

    createNotificationContainer() {
        const container = document.createElement('div');
        container.id = 'notificationContainer';
        container.className = 'notification-container';
        document.body.appendChild(container);
        return container;
    }

    showLoading(message = 'Loading...') {
        const loader = document.getElementById('loadingOverlay') || this.createLoadingOverlay();
        loader.querySelector('.loading-message').textContent = message;
        loader.style.display = 'flex';
    }

    hideLoading() {
        const loader = document.getElementById('loadingOverlay');
        if (loader) loader.style.display = 'none';
    }

    createLoadingOverlay() {
        const overlay = document.createElement('div');
        overlay.id = 'loadingOverlay';
        overlay.className = 'loading-overlay';
        overlay.innerHTML = `
            <div class="loading-content">
                <div class="loading-spinner"></div>
                <p class="loading-message">Loading...</p>
            </div>
        `;
        document.body.appendChild(overlay);
        return overlay;
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    editPortfolio(portfolio_id) {
        window.location.href = `/dashboard.html?edit=${portfolio_id}`;
    }

    publishPortfolio() {
        const isPublic = document.getElementById('isPublic')?.checked || false;
        this.showNotification(isPublic ? 'Portfolio is now public!' : 'Portfolio is private', 'success');
    }
}

// Initialize when DOM is ready
let generator;
document.addEventListener('DOMContentLoaded', () => {
    generator = new PortfolioGenerator();
});
