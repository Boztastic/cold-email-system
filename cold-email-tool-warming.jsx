import React, { useState, useEffect } from 'react';
import { Mail, Users, Settings, Send, Plus, Trash2, Upload, Download, Clock, CheckCircle, XCircle, AlertCircle, RefreshCw, Flame, Zap, Eye, EyeOff } from 'lucide-react';

// Configuration
const API_BASE_URL = 'http://localhost:3001';

export default function ColdEmailToolWithWarming() {
  const [activeTab, setActiveTab] = useState('warming');
  
  // Warming state
  const [warmingAccounts, setWarmingAccounts] = useState([]);
  const [newAccount, setNewAccount] = useState({
    name: '',
    email: '',
    password: '',
    smtpHost: '',
    smtpPort: '587',
    imapHost: '',
    imapPort: '993',
    enableAutoResponse: true
  });
  const [showPasswords, setShowPasswords] = useState({});
  const [warmingCampaign, setWarmingCampaign] = useState({
    id: null,
    status: 'idle',
    emailsPerDay: 10,
    duration: 30,
    stats: { sent: 0, failed: 0, responses: 0 }
  });
  
  // Regular campaign state
  const [contacts, setContacts] = useState([]);
  const [emailTemplate, setEmailTemplate] = useState({
    subject: '',
    body: '',
    fromName: '',
    fromEmail: ''
  });
  const [smtpSettings, setSmtpSettings] = useState({
    host: '',
    port: '587',
    username: '',
    password: '',
    secure: false
  });
  const [campaignSettings, setCampaignSettings] = useState({
    delayBetweenEmails: 30,
    dailyLimit: 50,
    unsubscribeLink: true,
    trackOpens: false
  });
  const [campaign, setCampaign] = useState({
    id: null,
    status: 'idle',
    sent: 0,
    failed: 0,
    total: 0
  });
  const [smtpTested, setSmtpTested] = useState(false);
  const [testing, setTesting] = useState(false);

  // Load warming accounts on mount
  useEffect(() => {
    fetchWarmingAccounts();
  }, []);

  // Poll warming campaign status
  useEffect(() => {
    if (warmingCampaign.status === 'active' && warmingCampaign.id) {
      const interval = setInterval(async () => {
        try {
          const response = await fetch(`${API_BASE_URL}/api/warming/campaigns/${warmingCampaign.id}`);
          const data = await response.json();
          
          if (data.success) {
            setWarmingCampaign(prev => ({
              ...prev,
              stats: data.campaign.stats,
              status: data.campaign.status
            }));
          }
        } catch (error) {
          console.error('Failed to fetch warming campaign status:', error);
        }
      }, 5000);
      
      return () => clearInterval(interval);
    }
  }, [warmingCampaign.status, warmingCampaign.id]);

  // Fetch warming accounts
  const fetchWarmingAccounts = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/warming/accounts`);
      const data = await response.json();
      if (data.success) {
        setWarmingAccounts(data.accounts);
      }
    } catch (error) {
      console.error('Failed to fetch warming accounts:', error);
    }
  };

  // Test SMTP connection for warming account
  const testAccountSMTP = async (account) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/smtp/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          host: account.smtpHost,
          port: parseInt(account.smtpPort),
          username: account.email,
          password: account.password,
          secure: account.smtpPort === '465'
        })
      });
      
      const data = await response.json();
      return data.success;
    } catch (error) {
      return false;
    }
  };

  // Test IMAP connection for warming account
  const testAccountIMAP = async (account) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/imap/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: account.email,
          password: account.password,
          imapHost: account.imapHost,
          imapPort: parseInt(account.imapPort)
        })
      });
      
      const data = await response.json();
      return data.success;
    } catch (error) {
      return false;
    }
  };

  // Add warming account
  const addWarmingAccount = async () => {
    if (!newAccount.email || !newAccount.password || !newAccount.smtpHost || !newAccount.imapHost) {
      alert('Please fill in all required fields');
      return;
    }

    // Test connections
    const smtpWorks = await testAccountSMTP(newAccount);
    const imapWorks = await testAccountIMAP(newAccount);

    if (!smtpWorks) {
      alert('SMTP connection failed. Please check your settings.');
      return;
    }

    if (!imapWorks) {
      alert('IMAP connection failed. Please check your settings.');
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/warming/accounts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newAccount)
      });
      
      const data = await response.json();
      
      if (data.success) {
        alert('✓ Account added successfully!');
        setNewAccount({
          name: '',
          email: '',
          password: '',
          smtpHost: '',
          smtpPort: '587',
          imapHost: '',
          imapPort: '993',
          enableAutoResponse: true
        });
        fetchWarmingAccounts();
      }
    } catch (error) {
      alert('Failed to add account: ' + error.message);
    }
  };

  // Remove warming account
  const removeWarmingAccount = async (id) => {
    if (!confirm('Remove this warming account?')) return;

    try {
      const response = await fetch(`${API_BASE_URL}/api/warming/accounts/${id}`, {
        method: 'DELETE'
      });
      
      const data = await response.json();
      
      if (data.success) {
        fetchWarmingAccounts();
      }
    } catch (error) {
      alert('Failed to remove account: ' + error.message);
    }
  };

  // Start warming campaign
  const startWarmingCampaign = async () => {
    if (warmingAccounts.length < 2) {
      alert('You need at least 2 accounts to start warming');
      return;
    }

    try {
      // Create campaign
      const createResponse = await fetch(`${API_BASE_URL}/api/warming/campaigns`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          emailsPerDay: warmingCampaign.emailsPerDay,
          duration: warmingCampaign.duration
        })
      });
      
      const createData = await createResponse.json();
      
      if (!createData.success) {
        alert('Failed to create warming campaign');
        return;
      }
      
      // Start campaign
      const startResponse = await fetch(`${API_BASE_URL}/api/warming/campaigns/${createData.campaignId}/start`, {
        method: 'POST'
      });
      
      const startData = await startResponse.json();
      
      if (startData.success) {
        setWarmingCampaign({
          ...warmingCampaign,
          id: createData.campaignId,
          status: 'active'
        });
        alert('✓ Warming campaign started!');
      }
    } catch (error) {
      alert('Error starting warming campaign: ' + error.message);
    }
  };

  // Stop warming campaign
  const stopWarmingCampaign = async () => {
    if (!warmingCampaign.id) return;

    try {
      const response = await fetch(`${API_BASE_URL}/api/warming/campaigns/${warmingCampaign.id}/stop`, {
        method: 'POST'
      });
      
      const data = await response.json();
      
      if (data.success) {
        setWarmingCampaign({
          ...warmingCampaign,
          status: 'stopped'
        });
      }
    } catch (error) {
      alert('Error stopping warming campaign: ' + error.message);
    }
  };

  // Rest of the regular campaign functions (abbreviated for space)
  const addContact = () => {
    setContacts([...contacts, { 
      id: Date.now(), 
      email: '', 
      firstName: '', 
      lastName: '', 
      company: '',
      customField1: '',
      status: 'pending'
    }]);
  };

  const removeContact = (id) => {
    setContacts(contacts.filter(c => c.id !== id));
  };

  const updateContact = (id, field, value) => {
    setContacts(contacts.map(c => 
      c.id === id ? { ...c, [field]: value } : c
    ));
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Flame className="w-10 h-10 text-orange-600" />
              <div>
                <h1 className="text-3xl font-bold text-gray-900">Advanced Cold Email Manager</h1>
                <p className="text-gray-600 mt-1">With account warming & AI auto-responses</p>
              </div>
            </div>
            
            {warmingCampaign.status === 'active' && (
              <div className="bg-orange-50 px-6 py-3 rounded-lg">
                <div className="flex items-center gap-4">
                  <Flame className="w-6 h-6 text-orange-600 animate-pulse" />
                  <div className="text-center">
                    <div className="text-2xl font-bold text-orange-600">{warmingCampaign.stats.sent}</div>
                    <div className="text-xs text-gray-600">Warming Sent</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-green-600">{warmingCampaign.stats.responses}</div>
                    <div className="text-xs text-gray-600">AI Responses</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Info Banner */}
        <div className="bg-gradient-to-r from-orange-50 to-yellow-50 border-l-4 border-orange-400 p-4 mb-6 rounded-r-lg">
          <div className="flex items-start">
            <Flame className="w-5 h-5 text-orange-600 mt-0.5 mr-3" />
            <div>
              <h3 className="font-semibold text-orange-900">Email Warming Feature</h3>
              <p className="text-orange-800 text-sm mt-1">
                Add multiple email accounts to send emails to each other automatically. The AI will generate 
                natural responses to build sender reputation before launching real campaigns. Start small (5-10 emails/day) 
                and gradually increase over 2-4 weeks for best results.
              </p>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="bg-white rounded-lg shadow-lg mb-6">
          <div className="flex border-b">
            {[
              { id: 'warming', label: 'Account Warming', icon: Flame },
              { id: 'contacts', label: 'Contacts', icon: Users },
              { id: 'email', label: 'Email Template', icon: Mail },
              { id: 'settings', label: 'Settings', icon: Settings },
              { id: 'campaign', label: 'Campaign', icon: Send }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-6 py-4 font-medium transition-colors ${
                  activeTab === tab.id
                    ? 'text-indigo-600 border-b-2 border-indigo-600'
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                <tab.icon className="w-5 h-5" />
                {tab.label}
              </button>
            ))}
          </div>

          <div className="p-6">
            {/* Warming Tab */}
            {activeTab === 'warming' && (
              <div>
                <h2 className="text-2xl font-bold text-gray-900 mb-6">Email Account Warming</h2>

                {/* Add Account Section */}
                <div className="bg-gradient-to-r from-orange-50 to-yellow-50 rounded-lg p-6 mb-6">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Add Warming Account</h3>
                  
                  <div className="grid grid-cols-2 gap-4 mb-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Name</label>
                      <input
                        type="text"
                        value={newAccount.name}
                        onChange={(e) => setNewAccount({...newAccount, name: e.target.value})}
                        placeholder="John Doe"
                        className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-orange-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Email*</label>
                      <input
                        type="email"
                        value={newAccount.email}
                        onChange={(e) => setNewAccount({...newAccount, email: e.target.value})}
                        placeholder="john@example.com"
                        className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-orange-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Password*</label>
                      <input
                        type="password"
                        value={newAccount.password}
                        onChange={(e) => setNewAccount({...newAccount, password: e.target.value})}
                        placeholder="App password"
                        className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-orange-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">SMTP Host*</label>
                      <input
                        type="text"
                        value={newAccount.smtpHost}
                        onChange={(e) => setNewAccount({...newAccount, smtpHost: e.target.value})}
                        placeholder="smtp.gmail.com"
                        className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-orange-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">SMTP Port</label>
                      <input
                        type="text"
                        value={newAccount.smtpPort}
                        onChange={(e) => setNewAccount({...newAccount, smtpPort: e.target.value})}
                        placeholder="587"
                        className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-orange-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">IMAP Host*</label>
                      <input
                        type="text"
                        value={newAccount.imapHost}
                        onChange={(e) => setNewAccount({...newAccount, imapHost: e.target.value})}
                        placeholder="imap.gmail.com"
                        className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-orange-500"
                      />
                    </div>
                  </div>

                  <div className="flex items-center gap-4 mb-4">
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={newAccount.enableAutoResponse}
                        onChange={(e) => setNewAccount({...newAccount, enableAutoResponse: e.target.checked})}
                        className="w-5 h-5 text-orange-600 rounded"
                      />
                      <span className="text-sm text-gray-700">Enable AI Auto-Response</span>
                    </label>
                  </div>

                  <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 mb-4">
                    <p className="text-sm text-blue-800">
                      <strong>Gmail Users:</strong> Use app password from Google Account → Security → App Passwords. 
                      IMAP host: imap.gmail.com (port 993), SMTP host: smtp.gmail.com (port 587)
                    </p>
                  </div>

                  <button
                    onClick={addWarmingAccount}
                    className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-orange-600 to-yellow-600 text-white rounded-lg hover:from-orange-700 hover:to-yellow-700 transition-all font-semibold"
                  >
                    <Plus className="w-5 h-5" />
                    Add Account (Will Test Connections)
                  </button>
                </div>

                {/* Accounts List */}
                <div className="mb-6">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">
                    Warming Accounts ({warmingAccounts.length})
                  </h3>
                  
                  {warmingAccounts.length === 0 ? (
                    <div className="text-center py-12 bg-gray-50 rounded-lg">
                      <Users className="w-16 h-16 text-gray-400 mx-auto mb-4" />
                      <p className="text-gray-600">No warming accounts yet. Add at least 2 accounts to start warming.</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {warmingAccounts.map(account => (
                        <div key={account.id} className="bg-white border-2 border-gray-200 rounded-lg p-4">
                          <div className="flex items-center justify-between">
                            <div className="flex-1">
                              <div className="flex items-center gap-3 mb-2">
                                <Mail className="w-5 h-5 text-indigo-600" />
                                <span className="font-semibold text-gray-900">{account.name || account.email}</span>
                                {account.enableAutoResponse && (
                                  <span className="px-2 py-1 bg-green-100 text-green-700 text-xs rounded-full flex items-center gap-1">
                                    <Zap className="w-3 h-3" />
                                    AI Enabled
                                  </span>
                                )}
                              </div>
                              <p className="text-sm text-gray-600">{account.email}</p>
                            </div>
                            <button
                              onClick={() => removeWarmingAccount(account.id)}
                              className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                            >
                              <Trash2 className="w-5 h-5" />
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Warming Campaign Settings */}
                <div className="bg-gray-50 rounded-lg p-6 mb-6">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Warming Campaign Settings</h3>
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Emails Per Day (Per Account)
                      </label>
                      <input
                        type="number"
                        value={warmingCampaign.emailsPerDay}
                        onChange={(e) => setWarmingCampaign({...warmingCampaign, emailsPerDay: parseInt(e.target.value)})}
                        min="1"
                        max="50"
                        className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-orange-500"
                      />
                      <p className="text-xs text-gray-600 mt-1">Start with 5-10, increase gradually</p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Duration (Days)
                      </label>
                      <input
                        type="number"
                        value={warmingCampaign.duration}
                        onChange={(e) => setWarmingCampaign({...warmingCampaign, duration: parseInt(e.target.value)})}
                        min="7"
                        max="90"
                        className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-orange-500"
                      />
                      <p className="text-xs text-gray-600 mt-1">Recommended: 14-30 days</p>
                    </div>
                  </div>
                </div>

                {/* Campaign Controls */}
                {warmingCampaign.status === 'idle' && warmingAccounts.length >= 2 && (
                  <button
                    onClick={startWarmingCampaign}
                    className="w-full flex items-center justify-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-lg hover:from-orange-700 hover:to-red-700 transition-all font-semibold text-lg shadow-lg"
                  >
                    <Flame className="w-6 h-6" />
                    Start Warming Campaign
                  </button>
                )}

                {warmingCampaign.status === 'active' && (
                  <div>
                    <div className="bg-white border-2 border-orange-200 rounded-lg p-8 text-center mb-4">
                      <div className="inline-block animate-pulse bg-orange-100 rounded-full p-6 mb-4">
                        <Flame className="w-12 h-12 text-orange-600" />
                      </div>
                      <h3 className="text-xl font-semibold text-gray-900 mb-2">Warming Campaign Active</h3>
                      <p className="text-gray-600 mb-4">
                        {warmingAccounts.length} accounts sending {warmingCampaign.emailsPerDay} emails/day each
                      </p>
                      <div className="grid grid-cols-3 gap-4 max-w-md mx-auto">
                        <div className="bg-orange-50 rounded-lg p-4">
                          <div className="text-2xl font-bold text-orange-600">{warmingCampaign.stats.sent}</div>
                          <div className="text-xs text-gray-600">Sent</div>
                        </div>
                        <div className="bg-green-50 rounded-lg p-4">
                          <div className="text-2xl font-bold text-green-600">{warmingCampaign.stats.responses}</div>
                          <div className="text-xs text-gray-600">AI Responses</div>
                        </div>
                        <div className="bg-red-50 rounded-lg p-4">
                          <div className="text-2xl font-bold text-red-600">{warmingCampaign.stats.failed}</div>
                          <div className="text-xs text-gray-600">Failed</div>
                        </div>
                      </div>
                    </div>

                    <button
                      onClick={stopWarmingCampaign}
                      className="w-full px-6 py-3 bg-gray-600 text-white rounded-lg hover:bg-gray-700 transition-colors font-semibold"
                    >
                      Stop Warming Campaign
                    </button>
                  </div>
                )}

                {/* How It Works */}
                <div className="bg-blue-50 border border-blue-200 rounded-lg p-6 mt-6">
                  <h3 className="font-semibold text-blue-900 mb-3">How Warming Works</h3>
                  <ol className="space-y-2 text-sm text-blue-800">
                    <li><strong>1. Automated Emails:</strong> Accounts send natural-looking emails to each other throughout the day</li>
                    <li><strong>2. AI Responses:</strong> Claude generates contextual, human-like responses automatically (1-4 hour delay)</li>
                    <li><strong>3. Gradual Increase:</strong> Start with 5-10 emails/day, increase by 5-10 every few days</li>
                    <li><strong>4. Reputation Building:</strong> Opens, clicks, and replies signal to email providers you're legitimate</li>
                    <li><strong>5. Duration:</strong> Run for 14-30 days before launching cold campaigns</li>
                  </ol>
                </div>
              </div>
            )}

            {/* Other tabs would go here - contacts, email, settings, campaign */}
            {/* For brevity, showing structure only */}
            
            {activeTab === 'contacts' && (
              <div>
                <h2 className="text-2xl font-bold text-gray-900 mb-4">Contact List</h2>
                <p className="text-gray-600">Standard contact management interface goes here...</p>
              </div>
            )}

            {activeTab === 'email' && (
              <div>
                <h2 className="text-2xl font-bold text-gray-900 mb-4">Email Template</h2>
                <p className="text-gray-600">Template editor goes here...</p>
              </div>
            )}

            {activeTab === 'settings' && (
              <div>
                <h2 className="text-2xl font-bold text-gray-900 mb-4">Campaign Settings</h2>
                <p className="text-gray-600">SMTP and campaign settings go here...</p>
              </div>
            )}

            {activeTab === 'campaign' && (
              <div>
                <h2 className="text-2xl font-bold text-gray-900 mb-4">Launch Campaign</h2>
                <p className="text-gray-600">Campaign launch interface goes here...</p>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          <h3 className="font-semibold text-gray-900 mb-3">🔥 Warming Best Practices</h3>
          <div className="grid grid-cols-2 gap-4 text-sm text-gray-700">
            <div><strong>✓ Start slow</strong> - 5-10 emails/day initially</div>
            <div><strong>✓ Use multiple domains</strong> - Don't put all eggs in one basket</div>
            <div><strong>✓ Vary timing</strong> - Emails sent throughout business hours</div>
            <div><strong>✓ Natural content</strong> - AI generates realistic conversations</div>
            <div><strong>✓ Monitor reputation</strong> - Check spam folder placement</div>
            <div><strong>✓ Be patient</strong> - 2-4 weeks for best results</div>
          </div>
        </div>
      </div>
    </div>
  );
}