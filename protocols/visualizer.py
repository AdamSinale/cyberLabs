import matplotlib.pyplot as plt


class Visualizer:
    def display_statistics(self, valid_flows, invalid_flows):
        # Example of visualizing the number of valid vs invalid flows
        labels = ['Valid Flows', 'Invalid Flows']
        sizes = [len(valid_flows), len(invalid_flows)]

        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
        plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
        plt.show()
