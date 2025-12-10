import copy
import logging
import datetime
import math
from lib_attrs.attr_recode import AttrRecord
from lib_view.marg_select import MarginalSelection
from lib_dataset.data_store import DataStore
from lib_composition.advanced_composition import AdvancedComposition

class Exp:
    def __init__(self, args):
        self.logger = logging.getLogger("exp")
        
        self.start_time = datetime.datetime.now()
        self.args = args
        
        self.epsilon = self.args['epsilon']
        self.dataset_name = args["dataset_name"]

        ########################################### main proceedure ###########################################
        # load dataset
        self.data_store = DataStore(self.args)
        self.load_data()
        self.logger.info("original dataset domain: %e" % (self.original_dataset.domain.size(),))
        
        self.data_store.save_one_marginal("original", self.original_dataset.df)

        self.num_records = self.original_dataset.df.shape[0]
        self.num_attributes = self.original_dataset.df.shape[1]
        self.delta = 1.0 / self.num_records ** 2

        self.privacy_budget_allocation()
        self.marginals = self.select_marginals(self.original_dataset)
        rho_per_attr = self.binning_rho / max(self.num_attributes, 1)
        self.gauss_sigma = self._calculate_sigma_from_rho(rho_per_attr)
        # recode groups low-count values 
        self.attr_recode = self.recode_attrs(self.gauss_sigma)
        
        self.logger.info('rho total %.6f | binning %.6f | selection %.6f | publish %.6f | binning sigma %.6f',
                         self.total_rho, self.binning_rho, self.selection_rho, self.publish_rho, self.gauss_sigma)

    ############################## preprocess ###########################################
    def load_data(self):
        self.logger.info("loading dataset %s" % (self.dataset_name,))
        self.original_dataset = self.data_store.load_processed_data()

    def privacy_budget_allocation(self):
        ratios = [
            self.args.get('binning_rho_ratio', 0.1),
            self.args.get('selection_rho_ratio', self.args.get('depend_epsilon_ratio', 0.1)),
            self.args.get('publish_rho_ratio', 0.8)
        ]
        ratio_sum = sum(ratios)
        if not math.isclose(ratio_sum, 1.0):
            ratios = [r / ratio_sum for r in ratios]
            self.logger.warning('rho ratios normalized to sum to 1.0: %s', ratios)

        self.binning_rho_ratio, self.selection_rho_ratio, self.publish_rho_ratio = ratios

        self.total_rho = self._calculate_total_rho(self.epsilon)
        self.binning_rho = self.total_rho * self.binning_rho_ratio
        self.selection_rho = self.total_rho * self.selection_rho_ratio
        self.publish_rho = self.total_rho * self.publish_rho_ratio

        # fallback epsilon splits for Laplace/noise-add variants
        self.depend_epsilon = self.epsilon * self.selection_rho_ratio
        self.remain_epsilon = self.epsilon * self.publish_rho_ratio
        self.remain_rho = self.publish_rho

        self.logger.info('privacy budget allocation (rho): binning %.4f | selection %.4f | publish %.4f',
                         self.binning_rho, self.selection_rho, self.publish_rho)

    def select_marginals(self, dataset):
        if self.args['is_cal_marginals']:
            self.logger.info("selecting marginals")
    
            select_args = copy.deepcopy(self.args)
            select_args['total_epsilon'] = self.epsilon
            select_args['depend_epsilon'] = self.depend_epsilon
            select_args['selection_rho'] = self.selection_rho
            select_args['publish_rho'] = self.publish_rho
            select_args['total_rho'] = self.total_rho
            select_args['delta'] = self.delta
            select_args['threshold'] = 5000
            
            marginal_selection = MarginalSelection(dataset, select_args, self.args)
            marginals = marginal_selection.select_marginals()
            self.data_store.save_marginal(marginals)
        else:
            marginals = self.data_store.load_marginal()
        
        return marginals

    def recode_attrs(self, sigma):
        self.logger.info("recoding attrs")
        
        # sigma = self._calculate_sigma(self.recode_epsilon, self.num_attributes)
        attr_recode = AttrRecord(self.original_dataset)
        attr_recode.recode(sigma)
    
        return attr_recode

    def _calculate_total_rho(self, epsilon):
        composition = AdvancedComposition()
        sigma = composition.gauss_zcdp(epsilon, self.delta, self.args['marg_add_sensitivity'], 1)
        
        return (self.args['marg_add_sensitivity'] ** 2 / (2.0 * sigma ** 2))
    
    def _calculate_sigma_from_rho(self, rho):
        return math.sqrt(self.args['marg_add_sensitivity'] ** 2 / (2.0 * max(rho, 1e-12)))
